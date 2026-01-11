import math
from dataclasses import dataclass
from typing import List, Tuple

COMMON_PASSWORDS = {
    "123456", "password", "qwerty", "12345678", "111111", "abc123",
    "123123", "admin", "letmein", "welcome", "iloveyou", "000000"
}

GUESS_RATES = {
    "ออนไลน์ (10 ครั้ง/วินาที)": 10,
    "ออนไลน์ (100 ครั้ง/วินาที)": 100,
    "ออฟไลน์ CPU (100M ครั้ง/วินาที)": 100_000_000,
    "ออฟไลน์ GPU (10B ครั้ง/วินาที)": 10_000_000_000,
}

@dataclass
class AnalysisResult:
    length: int
    charset_size: int
    entropy_bits: float
    score: int
    verdict: str
    warnings: List[str]
    suggestions: List[str]
    crack_times: List[Tuple[str, str]]


def _charset_size(pw: str) -> int:
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)

    size = 0
    if has_lower: size += 26
    if has_upper: size += 26
    if has_digit: size += 10
    if has_symbol: size += 33
    return max(size, 1)


def _entropy_bits(pw: str, charset: int) -> float:
    return len(pw) * math.log2(charset)


def _humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "< 1 วินาที"

    units = [
        ("ปี", 365 * 24 * 3600),
        ("วัน", 24 * 3600),
        ("ชั่วโมง", 3600),
        ("นาที", 60),
        ("วินาที", 1),
    ]

    parts = []
    remaining = int(seconds)

    for name, unit in units:
        if remaining >= unit:
            qty = remaining // unit
            remaining %= unit
            parts.append(f"{qty} {name}")
        if len(parts) == 2:
            break

    return ", ".join(parts) if parts else "< 1 วินาที"


def _avg_crack_time_seconds(pw_len: int, charset: int, guesses_per_sec: int) -> float:
    keyspace = charset ** pw_len
    return (keyspace / 2) / guesses_per_sec


def _looks_like_keyboard_pattern(pw: str) -> bool:
    patterns = ["qwerty", "asdf", "zxcv", "12345", "123456", "password"]
    lower = pw.lower()
    return any(p in lower for p in patterns)

def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def analyze_password(pw: str) -> AnalysisResult:
    warnings: List[str] = []
    suggestions: List[str] = []

    pw = pw or ""
    length = len(pw)
    charset = _charset_size(pw)
    entropy = _entropy_bits(pw, charset)

    if length == 0:
        return AnalysisResult(
            length=0,
            charset_size=1,
            entropy_bits=0.0,
            score=0,
            verdict="ว่างเปล่า",
            warnings=["คุณยังไม่ได้กรอกรหัสผ่าน"],
            suggestions=["กรอกรหัสผ่านเพื่อให้ระบบประเมิน"],
            crack_times=[],
        )

    if length < 8:
        warnings.append("สั้นเกินไป (< 8 ตัวอักษร)")
        suggestions.append("แนะนำอย่างน้อย 12–16 ตัวอักษร (แบบวลี/Passphrase ดีมาก)")

    if pw.lower() in COMMON_PASSWORDS:
        warnings.append("เป็นรหัสผ่านที่พบได้บ่อยมาก (เสี่ยงโดนเดาง่าย)")
        suggestions.append("หลีกเลี่ยงรหัสผ่านยอดนิยม และควรใช้รหัสผ่านที่ไม่ซ้ำกับเว็บอื่น")

    if _looks_like_keyboard_pattern(pw):
        warnings.append("คล้ายแพทเทิร์นที่เดาง่าย (เช่น qwerty/12345/asdf)")
        suggestions.append("หลีกเลี่ยงแพทเทิร์นเดาง่าย และเพิ่มความยาวของรหัสผ่าน")

    if len(set(pw)) <= 2 and length >= 6:
        warnings.append("ความหลากหลายน้อยมาก (ตัวอักษรซ้ำ ๆ)")
        suggestions.append("เพิ่มความหลากหลายของตัวอักษร และเพิ่มความยาว")

    if pw.isdigit():
        warnings.append("เป็นตัวเลขล้วน เดาได้ง่ายมาก")
        suggestions.append("เพิ่มตัวอักษร/สัญลักษณ์ หรือใช้ passphrase ที่ยาว")

    if entropy < 28:
        base = 20
    elif entropy < 50:
        base = 45
    elif entropy < 80:
        base = 70
    else:
        base = 90

    penalty = 0
    penalty += 25 if pw.lower() in COMMON_PASSWORDS else 0
    penalty += 15 if length < 8 else 0
    penalty += 15 if pw.isdigit() else 0
    penalty += 10 if _looks_like_keyboard_pattern(pw) else 0
    penalty += 10 if (len(set(pw)) <= 2 and length >= 6) else 0

    score = max(0, min(100, base - penalty))

    if score < 35:
        verdict = "อ่อน"
        bucket_warning = [
            "ความเสี่ยงสูง: อาจถูกเดา/สุ่มได้เร็ว โดยเฉพาะกรณีข้อมูลรั่ว"
        ]
        bucket_suggestions = [
            "เพิ่มความยาวเป็นอย่างน้อย 12–16 ตัวอักษร",
            "หลีกเลี่ยงคำที่พบบ่อย ชื่อ วันเกิด หรือแพทเทิร์นเดาง่าย",
            "ใช้รหัสผ่านไม่ซ้ำกันในแต่ละเว็บไซต์",
            "เปิดใช้ ยืนยันตัวตน2ชั้น ถ้าเป็นไปได้",
        ]
    elif score < 65:
        verdict = "พอใช้"
        bucket_warning = [
            "ยังมีความเสี่ยงอยู่: ถ้าโดนออฟไลน์เดา (เช่นแฮชหลุด) อาจถูกเดาได้"
        ]
        bucket_suggestions = [
            "เพิ่มความยาวให้ยาวขึ้นอีก (12–16+ จะปลอดภัยกว่า)",
            "เพิ่มความหลากหลาย (ตัวพิมพ์ใหญ่/สัญลักษณ์/สัญลักษณ์ผสมกัน)",
            "ใช้ Password Manager เพื่อสร้างรหัสผ่านแบบสุ่มและไม่ซ้ำ",
            "เปิดใช้ ยืนยันตัวตน2ชั้น ถ้าเป็นไปได้",
        ]
    elif score < 85:
        verdict = "แข็งแรง"
        bucket_warning = []
        bucket_suggestions = [
            "ดีมาก! รักษาแนวทางนี้ไว้ และอย่าใช้รหัสผ่านซ้ำข้ามเว็บ",
            "เปิดใช้ ยืนยันตัวตน2ชั้น ถ้าเป็นไปได้",
            "ถ้าเป็นไปได้ ใช้ Password Manager เพื่อจัดการรหัสผ่าน",
        ]
    else:
        verdict = "แข็งแรงมาก"
        bucket_warning = []
        bucket_suggestions = [
            "ยอดเยี่ยม! อย่าลืมใช้ไม่ซ้ำกันแต่ละเว็บ และเปิดใช้ ยืนยันตัวตน2ชั้น ถ้าเป็นไปได้",
            "เก็บรหัสผ่านด้วย Password Manager แทนการจำทุกอันเอง",
        ]

    crack_times: List[Tuple[str, str]] = []
    for label, rate in GUESS_RATES.items():
        sec = _avg_crack_time_seconds(length, charset, rate)
        crack_times.append((label, _humanize_seconds(sec)))

    if score < 65:
        warnings = _dedupe_keep_order(bucket_warning + warnings)
    else:
        warnings = _dedupe_keep_order(warnings) 
 
    suggestions = _dedupe_keep_order(bucket_suggestions + suggestions)

    return AnalysisResult(
        length=length,
        charset_size=charset,
        entropy_bits=entropy,
        score=score,
        verdict=verdict,
        warnings=warnings,
        suggestions=suggestions,
        crack_times=crack_times,
    )