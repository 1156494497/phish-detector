"""
评分阈值 / 权重校准工具（命令行）

用法：
    python calibrate.py                       # 默认扫描 ./samples 目录
    python calibrate.py --dir samples --ext eml,msg

目录约定：samples 下分两个子目录，子目录名即标签
    samples/phishing/   放已知钓鱼邮件
    samples/benign/     放已知正常邮件
    （标签 = 目录名，大小写不敏感：phishing / malicious / bad / scam 视为钓鱼；
     benign / ham / legit / ok / safe / clean 视为正常）

跑完后输出：
    1. 各邮件的得分与系统判定（基于当前 config 阈值）
    2. 混淆矩阵 + 准确率/召回率/F1
    3. 阈值扫描：把 SAFE/SUSPICIOUS 两个阈值在网格里扫一遍，输出每组的指标，
       帮你选最优切点，选好回填到 config.py 的 SCORE_SAFE_MAX / SCORE_SUSPICIOUS_MAX。

注意：本脚本会真实跑全套 analyzer（含 LLM、VT 调用），samples 多时较慢；
首次校准建议各放 10~20 封。VT 限速 4 次/分钟，VT 未配置时该指标自动缺失。
"""
import argparse
import asyncio
import os
import sys

# 让脚本可独立运行
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers import MsgParser, EmlParser, URLAnalyzer, AttachmentAnalyzer, ContentAnalyzer, VTChecker
from scoring import ScoringEngine
from models import RiskLevel

PHISH_LABELS = {"phishing", "malicious", "bad", "scam", "spam", "malware"}
BENIGN_LABELS = {"benign", "ham", "legit", "ok", "safe", "clean", "normal", "good"}


def label_from_dirname(name: str) -> str | None:
    n = name.lower()
    if n in PHISH_LABELS:
        return "phishing"
    if n in BENIGN_LABELS:
        return "benign"
    return None


def collect_samples(root: str, exts: tuple[str, ...]) -> list[tuple[str, str, str]]:
    """返回 [(文件路径, 标签, 子目录)]"""
    out = []
    if not os.path.isdir(root):
        return out
    for sub in sorted(os.listdir(root)):
        sub_path = os.path.join(root, sub)
        if not os.path.isdir(sub_path):
            continue
        label = label_from_dirname(sub)
        if label is None:
            print(f"[!] 跳过未知标签目录: {sub}（期望 phishing/benign）")
            continue
        for f in sorted(os.listdir(sub_path)):
            if f.lower().endswith(exts):
                out.append((os.path.join(sub_path, f), label, sub))
    return out


async def analyze_one(path: str, exts_tools) -> dict:
    msg_parser, eml_parser, url_analyzer, attachment_analyzer, content_analyzer, vt_checker, scoring_engine = exts_tools
    with open(path, "rb") as fp:
        data = fp.read()
    is_eml = path.lower().endswith(".eml")
    try:
        if is_eml:
            parsed_email, attachment_data = eml_parser.parse(data)
        else:
            parsed_email, attachment_data = msg_parser.parse(data)
        if is_eml:
            html_analysis = eml_parser._extract_html_signals(parsed_email.body_html)
        else:
            html_analysis = msg_parser._extract_html_signals(parsed_email.body_html)
        url_task = url_analyzer.analyze(parsed_email.urls, parsed_email.url_display_map, vt_checker=vt_checker)
        attachment_task = attachment_analyzer.analyze(parsed_email.attachments, attachment_data, vt_checker=vt_checker)
        content_task = asyncio.to_thread(
            content_analyzer.analyze, parsed_email.metadata, parsed_email.body_text,
            parsed_email.body_html, parsed_email.urls, parsed_email.attachments, html_analysis,
        )
        url_r, att_r, con_r = await asyncio.gather(url_task, attachment_task, content_task)
        result = scoring_engine.calculate(parsed_email.metadata, url_r, att_r, con_r, html_analysis)
        return {"ok": True, "score": result.total_score, "level": result.risk_level.value, "dims": [(d.name, d.score) for d in result.dimensions]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def predicted_label(score: int, safe_max: int, susp_max: int) -> str:
    if score <= safe_max:
        return "benign"
    if score <= susp_max:
        return "suspicious"
    return "phishing"


def confusion_matrix(rows: list[dict], safe_max: int, susp_max: int) -> dict:
    """把 suspicious 归到 phishing 一侧做二分类评估（钓鱼召回最关键）"""
    tp = fp = tn = fn = 0
    for r in rows:
        truth = "phishing" if r["truth"] == "phishing" else "benign"
        pred = "benign" if r["score"] <= safe_max else "phishing"  # suspicious 视为阳性
        if truth == "phishing" and pred == "phishing":
            tp += 1
        elif truth == "benign" and pred == "phishing":
            fp += 1
        elif truth == "benign" and pred == "benign":
            tn += 1
        else:
            fn += 1
    acc = (tp + tn) / max(tp + fp + tn + fn, 1)
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-9)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "acc": acc, "prec": prec, "rec": rec, "f1": f1}


def threshold_scan(rows: list[dict]) -> None:
    """网格扫描 SAFE/SUSPICIOUS 阈值，输出每组的二分类指标"""
    print("\n========== 阈值扫描（二分类：suspicious 归入阳性）==========")
    print(f"{'SAFE':>6} {'SUSP':>6} | {'Acc':>6} {'Prec':>6} {'Recall':>6} {'F1':>6} | {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}")
    print("-" * 70)
    best = None
    for safe in range(10, 51, 5):
        for susp in range(safe + 5, 96, 5):
            cm = confusion_matrix(rows, safe, susp)
            line = f"{safe:>6} {susp:>6} | {cm['acc']:>6.2f} {cm['prec']:>6.2f} {cm['rec']:>6.2f} {cm['f1']:>6.2f} | {cm['tp']:>3} {cm['fp']:>3} {cm['tn']:>3} {cm['fn']:>3}"
            print(line)
            # 选 F1 最高（召回优先：同 F1 取召回高者）
            if best is None or (cm["f1"], cm["rec"]) > (best[0]["f1"], best[0]["rec"]):
                best = (cm, safe, susp)
    if best:
        cm, safe, susp = best
        print("-" * 70)
        print(f"最优（F1 最高、召回优先）：SCORE_SAFE_MAX={safe}, SCORE_SUSPICIOUS_MAX={susp}")
        print(f"  Acc={cm['acc']:.2f} Prec={cm['prec']:.2f} Recall={cm['rec']:.2f} F1={cm['f1']:.2f}")
        print(f"  把这两个值回填到 config.py 即可。")


async def main():
    ap = argparse.ArgumentParser(description="钓鱼检测评分阈值/权重校准")
    ap.add_argument("--dir", default="samples", help="样本根目录（含 phishing/ 与 benign/ 子目录）")
    ap.add_argument("--ext", default="eml,msg", help="扫描的扩展名（逗号分隔）")
    args = ap.parse_args()

    exts = tuple("." + e.strip().lstrip(".") for e in args.ext.split(","))
    samples = collect_samples(args.dir, exts)
    if not samples:
        print(f"[!] 在 {args.dir} 下没有找到带标签的样本。")
        print("    请创建 samples/phishing/ 和 samples/benign/，各放几封邮件后重试。")
        return

    print(f"找到 {len(samples)} 个样本（钓鱼 {sum(1 for _,l,_ in samples if l=='phishing')}，"
          f"正常 {sum(1 for _,l,_ in samples if l=='benign')}）\n")

    # 复用 app 里的全局实例，保证和正式运行一致
    tools = (
        MsgParser(), EmlParser(), URLAnalyzer(), AttachmentAnalyzer(),
        ContentAnalyzer(), VTChecker(), ScoringEngine(),
    )

    rows = []
    for path, truth, _sub in samples:
        r = await analyze_one(path, tools)
        if not r["ok"]:
            print(f"[ERROR] {os.path.basename(path)}: {r['error']}")
            continue
        rows.append({"file": os.path.basename(path), "truth": truth, "score": r["score"], "level": r["level"], "dims": r["dims"]})
        print(f"{truth:9s} {r['score']:>3} [{r['level']:>10}] {os.path.basename(path)}  dims={r['dims']}")

    if not rows:
        print("[!] 没有成功分析的样本。")
        return

    from config import SCORE_SAFE_MAX, SCORE_SUSPICIOUS_MAX
    cm = confusion_matrix(rows, SCORE_SAFE_MAX, SCORE_SUSPICIOUS_MAX)
    print("\n========== 当前阈值下的混淆矩阵（二分类）==========")
    print(f"  当前 SCORE_SAFE_MAX={SCORE_SAFE_MAX}, SCORE_SUSPICIOUS_MAX={SCORE_SUSPICIOUS_MAX}")
    print(f"  TP={cm['tp']}  FP={cm['fp']}  TN={cm['tn']}  FN={cm['fn']}")
    print(f"  Acc={cm['acc']:.2f}  Prec={cm['prec']:.2f}  Recall={cm['rec']:.2f}  F1={cm['f1']:.2f}")
    print(f"  （FN={cm['fn']} 漏报钓鱼；FP={cm['fp']} 误报正常）")

    threshold_scan(rows)


if __name__ == "__main__":
    asyncio.run(main())