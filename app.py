"""
钓鱼邮件检测智能体 - FastAPI 主入口
"""
import asyncio
import logging
import re
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from urllib.parse import quote

from analyzers import MsgParser, EmlParser, URLAnalyzer, AttachmentAnalyzer, ContentAnalyzer, VTChecker
from scoring import ScoringEngine
from config import MAX_UPLOAD_SIZE, HOST, PORT
from cache import result_cache
from terminology import FindingsTranslator

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# 全局分析器实例
msg_parser = MsgParser()
eml_parser = EmlParser()
url_analyzer = URLAnalyzer()
attachment_analyzer = AttachmentAnalyzer()
content_analyzer = ContentAnalyzer()
vt_checker = VTChecker()
scoring_engine = ScoringEngine()

# 大白话翻译器：复用 content_analyzer 的 LLM 客户端（同一进程同模型），
# LLM 不可用时自动退化到正则兜底（terminology.translate_finding）
findings_translator = FindingsTranslator(llm_client=content_analyzer.llm_client)


# ============================================================
# 共享的"读取+校验+分析流水线"
# /api/analyze 与 /api/report 共用，避免双端点各跑一遍解析+analyzer。
# 以文件内容 sha256 为 key 做内存缓存：同封邮件先 analyze 再 report 只算一次。
# ============================================================
async def _run_detection(file: UploadFile) -> tuple:
    """
    返回 (data, detection_result, elapsed)
    命中缓存时 elapsed 为 0；未命中则跑完流水线并写入缓存。
    """
    start_time = time.time()

    # 1. 校验文件名
    if not file.filename:
        raise HTTPException(status_code=400, detail="未提供文件")
    filename_lower = file.filename.lower()
    if not (filename_lower.endswith(".msg") or filename_lower.endswith(".eml")):
        raise HTTPException(status_code=400, detail="仅支持 .msg 或 .eml 格式的邮件文件")

    # 2. 读取内容
    data = await file.read()
    if len(data) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"文件过大，最大支持 {MAX_UPLOAD_SIZE // 1024 // 1024}MB")
    if len(data) < 100:
        raise HTTPException(status_code=400, detail="文件内容过小，可能不是有效的邮件文件")

    # 3. 查缓存
    cached = result_cache.get(data)
    if cached is not None:
        elapsed = time.time() - start_time
        logger.info(f"缓存命中: {file.filename} (sha256={result_cache.make_key(data)[:8]}...)")
        return data, cached, elapsed

    # 4. 未命中：解析
    logger.info(f"开始分析: {file.filename} ({len(data)} bytes)")
    try:
        if filename_lower.endswith(".eml"):
            parsed_email, attachment_data = eml_parser.parse(data)
            html_analysis = eml_parser._extract_html_signals(parsed_email.body_html)
        else:
            parsed_email, attachment_data = msg_parser.parse(data)
            html_analysis = msg_parser._extract_html_signals(parsed_email.body_html)
    except re.error as e:
        fmt = "eml" if filename_lower.endswith(".eml") else "msg"
        logger.error(f"{fmt.upper()} 解析失败（RTF/正则异常）: {e}")
        raise HTTPException(status_code=400, detail=f"无法解析 .{fmt} 文件（RTF 格式损坏或内容异常）: {str(e)}")
    except Exception as e:
        fmt = "eml" if filename_lower.endswith(".eml") else "msg"
        logger.error(f"{fmt.upper()} 解析失败: {e}")
        raise HTTPException(status_code=400, detail=f"无法解析 .{fmt} 文件: {str(e)}")

    # 5. 并行分析各维度
    url_task = url_analyzer.analyze(parsed_email.urls, parsed_email.url_display_map, vt_checker=vt_checker)
    attachment_task = attachment_analyzer.analyze(parsed_email.attachments, attachment_data, vt_checker=vt_checker)
    content_task = asyncio.to_thread(
        content_analyzer.analyze,
        parsed_email.metadata, parsed_email.body_text, parsed_email.body_html,
        parsed_email.urls, parsed_email.attachments, html_analysis,
    )
    url_result, attachment_result, content_result = await asyncio.gather(url_task, attachment_task, content_task)

    # 6. 综合评分
    detection_result = scoring_engine.calculate(
        parsed_email.metadata, url_result, attachment_result, content_result, html_analysis,
    )

    elapsed = time.time() - start_time
    logger.info(
        f"分析完成: 总分={detection_result.total_score}, 风险等级={detection_result.risk_level.value}, 耗时={elapsed:.2f}s"
    )

    # 7. 写缓存
    result_cache.put(data, detection_result)

    return data, detection_result, elapsed


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    logger.info("=" * 60)
    logger.info("钓鱼邮件检测智能体启动")
    logger.info(f"LLM 状态: {'可用' if content_analyzer.llm_available else '不可用（使用规则引擎）'}")
    logger.info(f"LLM 地址: {content_analyzer.llm_client.base_url if content_analyzer.llm_client else 'N/A'}")
    logger.info(f"VirusTotal: {'已启用' if vt_checker.enabled else '未配置'}")
    logger.info(f"服务地址: http://{HOST}:{PORT}")
    logger.info("=" * 60)
    yield
    logger.info("钓鱼邮件检测智能体关闭")


app = FastAPI(
    title="钓鱼邮件检测智能体",
    description="企业内部钓鱼邮件检测工具，支持 .msg / .eml 文件上传分析",
    version="1.0.0",
    lifespan=lifespan,
)

# 静态文件服务
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def index():
    """返回前端页面"""
    return FileResponse("static/index.html")


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    """
    分析上传的邮件文件（.msg 或 .eml），返回 JSON 检测结果
    （命中缓存时复用结果，不再重复跑解析+analyzer+LLM/VT）
    """
    _, detection_result, elapsed = await _run_detection(file)
    return JSONResponse(
        content={
            "success": True,
            "elapsed_seconds": round(elapsed, 2),
            "result": detection_result.model_dump(),
        }
    )


@app.post("/api/report")
async def generate_report(file: UploadFile = File(...), inline: bool = False):
    """
    分析上传的邮件并返回详细 HTML 检测报告（大白话分层版）
    复用 /api/analyze 的同一套检测逻辑与缓存：同封邮件先 analyze 再 report 只算一次。
    默认 attachment 触发下载；?inline=1 改为在浏览器中查看。
    """
    _, detection_result, elapsed = await _run_detection(file)

    # 生成 HTML 报告（轻量，且在检测结果不变时可重现，无需缓存）
    from report_generator import ReportGenerator
    report_gen = ReportGenerator()
    # 用 LLM 把 findings 大批量改写成大白话，给第二层用；LLM 不可用时内部退化正则兜底
    plain_map = await asyncio.to_thread(findings_translator.translate_all, detection_result)
    report_html = report_gen.generate(detection_result, elapsed, file.filename, plain_map=plain_map)

    # 下载文件名：<主题>-检测报告.html
    subject = (detection_result.email_metadata.subject if detection_result.email_metadata else "") or "检测报告"
    subject = subject.replace("\n", " ").replace("\r", " ").strip() or "检测报告"
    safe_subject = subject.replace(".msg", "").replace(".eml", "")[:60]
    download_name = quote(f"{safe_subject}-检测报告.html")

    disposition = "inline" if inline else "attachment"
    return HTMLResponse(
        content=report_html,
        headers={
            "Content-Disposition": f'{disposition}; filename="{download_name}"; filename*=UTF-8\'\'{download_name}',
        },
    )


@app.get("/api/health")
async def health_check():
    """健康检查"""
    return {
        "status": "ok",
        "llm_available": content_analyzer.llm_available,
        "vt_enabled": vt_checker.enabled,
        "cache": result_cache.stats(),
    }


@app.get("/api/debug/score-schema")
async def score_schema_debug():
    """
    返回当前所有评分阈值 + 权重的含义说明，
    用于前端"配置说明"面板或校准工具。
    """
    from config import (
        SCORE_SAFE_MAX, SCORE_SUSPICIOUS_MAX,
        WEIGHT_URL, WEIGHT_ATTACHMENT, WEIGHT_CONTENT, WEIGHT_SENDER,
        DIM_AMP_URL, DIM_AMP_ATTACHMENT, DIM_AMP_CONTENT, DIM_AMP_SENDER,
        SENDER_SCORE_BRAND_MISMATCH, SENDER_SCORE_NAME_EMAIL_MISMATCH,
        SENDER_SCORE_FREE_PROVIDER, SENDER_SCORE_SUSPICIOUS_TLD,
        SENDER_SCORE_INTERNAL_TYPOSQUAT, SENDER_SCORE_INTERNAL_NAME_CONTAIN,
        SENDER_SCORE_EMPTY_SENDER,
        SENDER_SCORE_SPF_FAIL, SENDER_SCORE_SPF_SOFTFAIL, SENDER_SCORE_SPF_NONE,
        SENDER_SCORE_DKIM_FAIL, SENDER_SCORE_DKIM_NONE,
        SENDER_SCORE_DMARC_FAIL, SENDER_SCORE_DMARC_NONE,
        SENDER_SCORE_REPLYTO_MISMATCH, SENDER_SCORE_RETURNPATH_MISMATCH,
        CORR_HIGH_THRESHOLD, CORR_MEDIUM_THRESHOLD,
        CORR_BONUS_3HIGH, CORR_BONUS_2HIGH, CORR_BONUS_ALL_MEDIUM,
        CORR_BONUS_PATTERN, CORR_BONUS_MAX,
        HTML_BONUS_PER_FINDING, HTML_BONUS_MAX,
    )
    return {
        "thresholds": {
            "SCORE_SAFE_MAX": {
                "value": SCORE_SAFE_MAX,
                "meaning": "综合得分 0-30 → 安全，无需处置",
                "adjust_example": "若误报率高 → 调低至 25；漏报多 → 保持 30",
            },
            "SCORE_SUSPICIOUS_MAX": {
                "value": SCORE_SUSPICIOUS_MAX,
                "meaning": "综合得分 31-60 → 可疑，建议人工复核",
                "adjust_example": "若误报率高 → 调低至 50；漏报多 → 调高至 70",
            },
        },
        "weights": {
            "URL": {"value": WEIGHT_URL, "meaning": "链接风险权重 30%"},
            "ATTACHMENT": {"value": WEIGHT_ATTACHMENT, "meaning": "附件风险权重 25%"},
            "CONTENT": {"value": WEIGHT_CONTENT, "meaning": "内容风险权重 30%"},
            "SENDER": {"value": WEIGHT_SENDER, "meaning": "发件人风险权重 15%"},
        },
        "dimension_amplifiers": {
            "URL": {"value": DIM_AMP_URL, "meaning": "链接维度放大系数 >1 放大风险"},
            "ATTACHMENT": {"value": DIM_AMP_ATTACHMENT, "meaning": "附件维度放大系数"},
            "CONTENT": {"value": DIM_AMP_CONTENT, "meaning": "内容维度放大系数"},
            "SENDER": {"value": DIM_AMP_SENDER, "meaning": "发件人维度放大系数"},
        },
        "sender_item_scores": {
            "BRAND_MISMATCH": SENDER_SCORE_BRAND_MISMATCH,
            "NAME_EMAIL_MISMATCH": SENDER_SCORE_NAME_EMAIL_MISMATCH,
            "FREE_PROVIDER": SENDER_SCORE_FREE_PROVIDER,
            "SUSPICIOUS_TLD": SENDER_SCORE_SUSPICIOUS_TLD,
            "INTERNAL_TYPOSQUAT": SENDER_SCORE_INTERNAL_TYPOSQUAT,
            "INTERNAL_NAME_CONTAIN": SENDER_SCORE_INTERNAL_NAME_CONTAIN,
            "EMPTY_SENDER": SENDER_SCORE_EMPTY_SENDER,
            "SPF_FAIL": SENDER_SCORE_SPF_FAIL,
            "SPF_SOFTFAIL": SENDER_SCORE_SPF_SOFTFAIL,
            "SPF_NONE": SENDER_SCORE_SPF_NONE,
            "DKIM_FAIL": SENDER_SCORE_DKIM_FAIL,
            "DKIM_NONE": SENDER_SCORE_DKIM_NONE,
            "DMARC_FAIL": SENDER_SCORE_DMARC_FAIL,
            "DMARC_NONE": SENDER_SCORE_DMARC_NONE,
            "REPLYTO_MISMATCH": SENDER_SCORE_REPLYTO_MISMATCH,
            "RETURNPATH_MISMATCH": SENDER_SCORE_RETURNPATH_MISMATCH,
        },
        "correlation": {
            "CORR_HIGH_THRESHOLD": CORR_HIGH_THRESHOLD,
            "CORR_MEDIUM_THRESHOLD": CORR_MEDIUM_THRESHOLD,
            "CORR_BONUS_3HIGH": CORR_BONUS_3HIGH,
            "CORR_BONUS_2HIGH": CORR_BONUS_2HIGH,
            "CORR_BONUS_ALL_MEDIUM": CORR_BONUS_ALL_MEDIUM,
            "CORR_BONUS_PATTERN": CORR_BONUS_PATTERN,
            "CORR_BONUS_MAX": CORR_BONUS_MAX,
        },
        "html_bonus": {
            "HTML_BONUS_PER_FINDING": HTML_BONUS_PER_FINDING,
            "HTML_BONUS_MAX": HTML_BONUS_MAX,
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=HOST,
        port=PORT,
        reload=True,
    )
