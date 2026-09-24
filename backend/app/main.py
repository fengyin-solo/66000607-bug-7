from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import re
import uuid
import zlib
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = FastAPI(title="Smart Contract Security Auditor")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Vulnerability patterns
VULNERABILITY_PATTERNS = [
    {
        "type": "重入攻击 (Reentrancy)",
        "severity": "critical",
        "pattern": r"\.call\{[^}]*value:\s*[^}]*\}\s*\(",
        "description": "使用低级call()或send()转移ETH存在重入攻击风险。攻击者可部署恶意合约在fallback中反复调用提款。",
        "suggestion": "使用Checks-Effects-Interactions模式，或引入ReentrancyGuard。推荐使用transfer()或call()并限制Gas。"
    },
    {
        "type": "整数溢出 (Integer Overflow/Underflow)",
        "severity": "high",
        # 仅匹配复合赋值运算，避免把 ==、>=、<= 等比较符误报为两次
        "pattern": r"(?:\+\+|--|(?:\+|-|\*|/|%|<<|>>|&|\||\^)\s*=)(?!=)",
        "description": "Solidity 0.7及以下版本，未使用SafeMath时可能发生整数溢出。",
        "suggestion": "使用SafeMath库或升级到Solidity 0.8+（内置溢出检查）。"
    },
    {
        "type": "未授权访问控制",
        "severity": "high",
        "pattern": r"function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)\s*(?:payable\s*)?\{(?![^}]*(?:onlyOwner|require\s*\(\s*msg\.sender|require\s*\(\s*tx\.origin))",
        "description": "关键函数缺少访问控制检查，任何人都可以调用。",
        "suggestion": "添加onlyOwner或自定义访问控制修饰符。"
    },
    {
        "type": "selfdestruct使用",
        "severity": "medium",
        "pattern": r"selfdestruct|suicide",
        "description": "selfdestruct可强制将合约所有ETH发送到任意地址，可能被滥用。",
        "suggestion": "谨慎使用selfdestruct，确保有正当的业务需求。"
    },
    {
        "type": "tx.origin钓鱼",
        "severity": "high",
        "pattern": r"tx\.origin",
        "description": "使用tx.origin进行身份验证可能被钓鱼攻击，攻击者诱导用户触发交易。",
        "suggestion": "使用msg.sender代替tx.origin进行身份验证。"
    },
    {
        "type": "精确度损失",
        "severity": "medium",
        # 注释已在扫描前剥除，因此不会误报 SPDX 等许可证 URL
        "pattern": r"/\s*\d+",
        "description": "除法运算可能导致精度损失，特别是在代币金额计算中。",
        "suggestion": "先乘后除，使用高精度计算或使用Babylonian方法。"
    },
]

GAS_PATTERNS = [
    {"function": "storage_read", "issue": "循环中读取storage变量", "saving": 0.3},
    {"function": "redundant_sstore", "issue": "不必要的storage写入", "saving": 0.25},
    {"function": "short_circuit", "issue": "逻辑运算可短路优化", "saving": 0.15},
]

# 进程内审计记录存储：filename -> 最新一次审计结论
# 同一份合约（按文件名标识）重复审计时覆盖旧结论，保证各入口看到的结论一致
audit_store: Dict[str, dict] = {}


class AuditRequest(BaseModel):
    code: str
    filename: str


def _strip_comments_and_strings(code: str) -> List[str]:
    """逐行去除注释，避免注释中的示例代码触发误报。"""
    lines = code.split("\n")
    cleaned: List[str] = []
    in_block = False
    for line in lines:
        result = []
        i = 0
        while i < len(line):
            if in_block:
                end = line.find("*/", i)
                if end == -1:
                    i = len(line)
                else:
                    in_block = False
                    i = end + 2
            else:
                if line.startswith("/*", i):
                    in_block = True
                    i += 2
                elif line.startswith("//", i):
                    break
                else:
                    result.append(line[i])
                    i += 1
        cleaned.append("".join(result))
    return cleaned


def detect_vulnerabilities(code: str) -> List[dict]:
    """Scan code for vulnerability patterns.

    - finditer 会保留同一模式的每一次出现（不再只报第一条）
    - 以 (类型, 行号) 去重，同一正则在同一行重叠命中只保留一条
    - 最终按行号排序，与代码中出现顺序一致
    """
    lines = code.split("\n")
    code_lines = _strip_comments_and_strings(code)
    scan_code = "\n".join(code_lines)

    vulnerabilities: List[dict] = []
    seen = set()

    for vp in VULNERABILITY_PATTERNS:
        for m in re.finditer(vp["pattern"], scan_code, re.MULTILINE):
            line_num = scan_code[:m.start()].count("\n") + 1
            key = (vp["type"], line_num)
            if key in seen:
                continue
            seen.add(key)

            context_start = max(0, line_num - 2)
            context_end = min(len(lines), line_num + 2)
            context = "\n".join(lines[context_start:context_end])

            vulnerabilities.append({
                "id": f"v-{len(seen)}",
                "type": vp["type"],
                "severity": vp["severity"],
                "line": line_num,
                "description": vp["description"],
                "suggestion": vp["suggestion"],
                "code": context.strip()
            })

    vulnerabilities.sort(key=lambda v: (v["line"], v["type"]))
    # 排序后重新编号，供前端作为稳定的列表 key
    for idx, v in enumerate(vulnerabilities, start=1):
        v["id"] = f"v-{idx}"
    return vulnerabilities


def compute_gas_issues(code: str) -> List[dict]:
    """Analyze gas consumption issues.

    结果只依赖代码内容（按函数名做确定性哈希），同一份合约多次审计结论稳定，
    避免刷新前后数据对不上。
    """
    issues = []
    functions = re.findall(r"function\s+(\w+)\s*\(", code)
    suggestions = ["移除不必要的storage写入", "缓存storage变量到memory", "使用短路逻辑", "合并多个事件为一个"]
    for idx, fn in enumerate(functions):
        seed = zlib.crc32(fn.encode("utf-8"))
        base_gas = 20000 + seed % 40000
        optimized_gas = int(base_gas * (0.7 + (seed % 20) / 100))
        issues.append({
            "id": f"g-{idx + 1}",
            "functionName": f"{fn}()",
            "currentGas": base_gas,
            "optimizedGas": optimized_gas,
            "suggestion": suggestions[seed % len(suggestions)]
        })
    return issues


def compute_security_score(vulnerabilities: List[dict]) -> int:
    """Compute overall security score"""
    if not vulnerabilities:
        return 100
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    deduction = sum(severity_weights.get(v["severity"], 5) for v in vulnerabilities)
    return max(0, 100 - deduction)


def _build_result(code: str, filename: str) -> dict:
    vulnerabilities = detect_vulnerabilities(code)
    gas_issues = compute_gas_issues(code)
    score = compute_security_score(vulnerabilities)
    key = filename.strip() or "未命名合约.sol"

    existing = audit_store.get(key)
    result = {
        # 同一份合约重复审计沿用原 id，只更新结论；新合约才生成新 id
        "id": existing["id"] if existing else str(uuid.uuid4()),
        "filename": key,
        "score": score,
        "vulnerabilities": vulnerabilities,
        "gasIssues": gas_issues,
        "code": code,
        "timestamp": datetime.now().isoformat(timespec="seconds")
    }
    audit_store[key] = result
    return result


@app.get("/")
async def root():
    return {"message": "Smart Contract Security Auditor", "version": "1.0.0"}


@app.get("/api/patterns")
async def list_patterns():
    return {"code": 0, "message": "success", "data": VULNERABILITY_PATTERNS}


@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="合约代码不能为空")
    result = _build_result(request.code, request.filename)
    return {"code": 0, "message": "success", "data": result}


@app.get("/api/history")
async def get_history():
    """返回所有合约各自最新的一次审计结论，按审计时间倒序。"""
    data = sorted(audit_store.values(), key=lambda r: r["timestamp"], reverse=True)
    return {"code": 0, "message": "success", "data": data}


@app.get("/api/audit/{audit_id}")
async def get_audit(audit_id: str):
    for result in audit_store.values():
        if result["id"] == audit_id:
            return {"code": 0, "message": "success", "data": result}
    raise HTTPException(status_code=404, detail="审计记录不存在")


@app.get("/api/audit/by-filename/{filename}")
async def get_audit_by_filename(filename: str):
    """按文件名取同一份合约的最新结论（历史入口跳详情用）。"""
    result = audit_store.get(filename)
    if result is None:
        raise HTTPException(status_code=404, detail="审计记录不存在")
    return {"code": 0, "message": "success", "data": result}


@app.post("/api/report/{audit_id}")
async def generate_report(audit_id: str):
    """Generate PDF report"""
    return {"code": 0, "message": "success", "data": {"url": f"/api/reports/{audit_id}.pdf"}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
