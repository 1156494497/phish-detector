"""
附件分析器
检测附件的文件类型、恶意宏、文件伪装等风险
"""
import hashlib
import logging
import re
import zipfile
from io import BytesIO

import filetype
from oletools.olevba import VBA_Parser

from models import AttachmentDetail, AttachmentAnalysisResult, AttachmentInfo
from config import DANGEROUS_EXTENSIONS, MEDIUM_RISK_EXTENSIONS, SAFE_EXTENSIONS

logger = logging.getLogger(__name__)

# 可疑 VBA 宏关键字
SUSPICIOUS_VBA_KEYWORDS = [
    "AutoOpen", "Document_Open", "AutoExec",
    "Shell", "CreateObject", "WScript.Shell",
    "URLDownloadToFile", "URLDownloadToCache",
    "PowerShell", "powershell",
    "Exec", "Execute",
    "Environ", "GetEnvironmentVariable",
    "CallByName", "RegWrite", "RegRead",
    "SaveToFile", "ADODB.Stream",
    "WinHttpReq", "MSXML2",
    "Scripting.FileSystemObject",
    "vbOpen", "vbCreate",
]

# 双重扩展名检测模式
DOUBLE_EXT_PATTERN = re.compile(r'\.\w+\.\w+$')


class AttachmentAnalyzer:
    """分析邮件附件的安全风险"""

    async def analyze(self, attachments: list[AttachmentInfo], attachment_data: dict[str, bytes], vt_checker=None) -> AttachmentAnalysisResult:
        """
        分析所有附件

        Args:
            attachments: 附件元信息列表
            attachment_data: 附件二进制数据映射 {filename: data}
            vt_checker: 可选的 VirusTotal 查询器

        Returns:
            AttachmentAnalysisResult
        """
        if not attachments:
            return AttachmentAnalysisResult(
                attachments_analyzed=[],
                max_score=0,
                findings=["邮件中无附件"]
            )

        results = []
        all_findings = []

        for att in attachments:
            data = attachment_data.get(att.filename, b"")
            detail = self._analyze_single_attachment(att, data)
            # VirusTotal 文件哈希查询（异步）
            if vt_checker and vt_checker.enabled and detail.sha256:
                vt_result = await vt_checker.check_file_hash(detail.sha256)
                if vt_result.get("checked"):
                    detail.vt_checked = True
                    detail.vt_malicious_count = vt_result.get("malicious_count", 0)
                    detail.vt_total_engines = vt_result.get("total_engines", 0)
                    detail.vt_link = vt_result.get("link", "")
                    # VT 评分: 多引擎报毒
                    if detail.vt_total_engines > 0 and detail.vt_malicious_count > 0:
                        vt_score = min(int(detail.vt_malicious_count / detail.vt_total_engines * 100), 95)
                        detail.score = min(max(detail.score, vt_score), 100)
                    detail.findings.extend(vt_result.get("findings", []))
            results.append(detail)
            all_findings.extend(detail.findings)

        max_score = max((r.score for r in results), default=0)

        return AttachmentAnalysisResult(
            attachments_analyzed=results,
            max_score=max_score,
            findings=all_findings,
        )

    def _analyze_single_attachment(self, att: AttachmentInfo, data: bytes) -> AttachmentDetail:
        """分析单个附件"""
        findings = []
        score = 0
        filename = att.filename
        ext = att.extension.lower()

        detail = AttachmentDetail(
            filename=filename,
            extension=ext,
            sha256=att.sha256,
            size=att.size,
        )

        # 1. 双重扩展名检测（如 report.pdf.exe）
        if self._has_double_extension(filename):
            score += 95
            detail.file_type_danger = "high"
            findings.append(f"双重扩展名检测: {filename} — 可能伪装文件类型")
            detail.score = min(score, 100)
            detail.findings = findings
            return detail

        # 2. 文件类型危险等级
        if ext in DANGEROUS_EXTENSIONS:
            score += 90
            detail.file_type_danger = "high"
            findings.append(f"高危文件类型: {ext} ({filename})")
        elif ext in MEDIUM_RISK_EXTENSIONS:
            detail.file_type_danger = "medium"
            score += 10  # 基础分，后续宏检测会加分
            findings.append(f"中危文件类型: {ext}，需进一步检测宏")
        elif ext in SAFE_EXTENSIONS:
            detail.file_type_danger = "low"
            score += 5
        else:
            detail.file_type_danger = "unknown"
            score += 40
            findings.append(f"未知文件类型: {ext} ({filename})")

        # 3. 文件类型伪装检测（magic bytes vs 扩展名）
        if data and len(data) > 10:
            is_disguised, expected, actual = self._check_file_disguise(filename, data)
            if is_disguised:
                score += 70
                detail.is_disguised = True
                detail.expected_type = expected
                detail.actual_type = actual
                findings.append(f"文件类型伪装: 扩展名为 {ext}，但实际类型为 {actual}")

        # 3.5 ZIP 压缩包内容检查（含密码保护检测）
        if ext in {".zip", ".rar", ".7z"} and data and len(data) > 20:
            zip_dangerous, zip_findings, is_encrypted, inner_files = self._check_zip_contents(data, filename)
            detail.inner_files = inner_files
            if is_encrypted:
                detail.is_encrypted = True
                score += 50
                findings.append(f"压缩包已加密（密码保护），无法检查内部内容 — 常用于逃避安全扫描: {filename}")
            if zip_dangerous:
                score += 65
                detail.file_type_danger = "high"
                findings.append(f"压缩包内含高危文件: {', '.join(zip_findings[:5])}")
            elif zip_findings:
                findings.extend(zip_findings)

        # 4. 恶意宏检测（针对 Office 文档）
        if ext in {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm"} and data:
            has_macro, macro_keywords = self._check_malicious_macro(data, filename)
            detail.has_macro = has_macro
            detail.macro_suspicious_keywords = macro_keywords
            if has_macro:
                if macro_keywords:
                    score += 85
                    findings.append(f"检测到恶意宏，包含可疑关键字: {', '.join(macro_keywords)}")
                else:
                    score += 40
                    findings.append(f"文档包含 VBA 宏（未发现明显恶意行为）")

        # 5. 空文件检测
        if len(data) == 0 and att.size == 0:
            findings.append(f"附件为空文件: {filename}")
            score += 20

        # 6. 超大文件检测
        if att.size > 20 * 1024 * 1024:  # > 20MB
            findings.append(f"附件体积异常: {att.size / 1024 / 1024:.1f}MB")
            score += 10

        detail.score = min(score, 100)
        detail.findings = findings
        return detail

    def _has_double_extension(self, filename: str) -> bool:
        """检测双重扩展名"""
        # 匹配类似 "report.pdf.exe" 的模式
        parts = filename.rsplit(".", 2)
        if len(parts) >= 3:
            # 最后两个部分都是扩展名格式
            last_ext = "." + parts[-1].lower()
            second_ext = "." + parts[-2].lower()
            if last_ext in DANGEROUS_EXTENSIONS and second_ext in (MEDIUM_RISK_EXTENSIONS | SAFE_EXTENSIONS):
                return True
        return False

    def _check_zip_contents(self, data: bytes, filename: str) -> tuple[bool, list[str], bool, list[str]]:
        """
        检查压缩包内部文件，判断是否包含恶意载荷
        Returns: (has_dangerous_content, findings, is_encrypted, inner_files)
        """
        findings = []
        has_dangerous = False
        is_encrypted = False
        inner_files = []

        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    inner_files.append(info.filename)
                    name = info.filename.lower()

                    # 检测密码保护（flag_bits 第0位为1表示加密）
                    if info.flag_bits & 0x1:
                        is_encrypted = True

                    # 检查内部文件扩展名
                    for ext in DANGEROUS_EXTENSIONS:
                        if name.endswith(ext):
                            has_dangerous = True
                            findings.append(f"{info.filename} ({ext})")
                            break
                    # 检查双重扩展名
                    if not has_dangerous and "." in name:
                        parts = name.rsplit(".", 2)
                        if len(parts) >= 3:
                            last_ext = "." + parts[-1]
                            if last_ext in DANGEROUS_EXTENSIONS:
                                has_dangerous = True
                                findings.append(f"{info.filename} (双重扩展名)")
                zf.close()
        except zipfile.BadZipFile:
            # 不是标准 ZIP 格式（可能是 RAR/7z 或其他）
            findings.append(f"压缩包 {filename} 不是标准 ZIP 格式，无法解包检查")
        except Exception as e:
            logger.warning(f"ZIP 分析失败 [{filename}]: {e}")

        return has_dangerous, findings, is_encrypted, inner_files

    def _check_file_disguise(self, filename: str, data: bytes) -> tuple[bool, str, str]:
        """
        检测文件类型伪装
        Returns: (is_disguised, expected_type, actual_type)
        """
        try:
            kind = filetype.guess(data)
            if kind is None:
                return False, "", ""

            actual_mime = kind.mime
            actual_ext = "." + kind.extension

            # 获取文件扩展名
            ext = ""
            if "." in filename:
                ext = "." + filename.rsplit(".", 1)[-1].lower()

            # 检查扩展名与实际类型是否匹配
            ext_to_mime = {
                ".pdf": "application/pdf",
                ".doc": "application/msword",
                ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ".xls": "application/vnd.ms-excel",
                ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ".ppt": "application/vnd.ms-powerpoint",
                ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".png": "image/png",
                ".gif": "image/gif",
                ".zip": "application/zip",
                ".exe": "application/x-dos_ms_application",
            }

            expected_mime = ext_to_mime.get(ext, "")
            if expected_mime and expected_mime != actual_mime:
                # 宽松匹配：Office 文档可能是 OLE 格式
                if ext in {".doc", ".xls", ".ppt"} and "ole" in actual_mime.lower():
                    return False, expected_mime, actual_mime
                if ext in {".docx", ".xlsx", ".pptx"} and "zip" in actual_mime.lower():
                    return False, expected_mime, actual_mime
                return True, expected_mime, actual_mime

        except Exception as e:
            logger.warning(f"文件类型检测失败: {e}")

        return False, "", ""

    def _check_malicious_macro(self, data: bytes, filename: str) -> tuple[bool, list[str]]:
        """
        检测恶意 VBA 宏
        Returns: (has_macro, suspicious_keywords_found)
        """
        try:
            # 将数据写入临时 BytesIO
            vbaparser = VBA_Parser(filename, data)

            if not vbaparser.detect_vba_macros():
                return False, []

            # 提取宏代码并分析
            found_keywords = []
            for (filename_vba, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                if vba_code:
                    code_lower = vba_code.lower()
                    for keyword in SUSPICIOUS_VBA_KEYWORDS:
                        if keyword.lower() in code_lower:
                            if keyword not in found_keywords:
                                found_keywords.append(keyword)

            vbaparser.close()
            return True, found_keywords

        except Exception as e:
            logger.warning(f"宏检测失败 [{filename}]: {e}")
            return False, []
