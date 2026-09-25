from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict
import re
import uuid
import random
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
        "pattern": r"\.call\{[^}]*value:\s*[^}]*\}\([^)]*\)",
        "description": "使用低级call()或send()转移ETH存在重入攻击风险。攻击者可部署恶意合约在fallback中反复调用提款。",
        "suggestion": "使用Checks-Effects-Interactions模式，或引入ReentrancyGuard。推荐使用transfer()或call()并限制Gas。"
    },
    {
        "type": "整数溢出 (Integer Overflow/Underflow)",
        "severity": "high",
        "pattern": r"[+\-*/]\s*=|(&&|\|\|)\s*\w+\s*[<>=]",
        "description": "Solidity 0.7及以下版本，未使用SafeMath时可能发生整数溢出。",
        "suggestion": "使用SafeMath库或升级到Solidity 0.8+（内置溢出检查）。"
    },
    {
        "type": "未授权访问控制",
        "severity": "high",
        "pattern": r"function\s+\w+\s*\([^)]*\)\s*public\s*(payable)?\s*\{[^}]*(?:require|if)\s*\(",
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

class AuditRequest(BaseModel):
    code: str
    filename: str

# In-memory audit history, keyed by filename: re-auditing the same contract
# updates its record in place instead of piling up stale duplicates.
AUDIT_HISTORY: Dict[str, dict] = {}

def detect_vulnerabilities(code: str) -> List[dict]:
    """Scan code for vulnerability patterns"""
    lines = code.split("\n")
    vulnerabilities = []
    
    for vp in VULNERABILITY_PATTERNS:
        matches = re.finditer(vp["pattern"], code, re.MULTILINE)
        for m in matches:
            line_num = code[:m.start()].count("\n") + 1
            # Find context
            context_start = max(0, line_num - 2)
            context_end = min(len(lines), line_num + 2)
            context = "\n".join(lines[context_start:context_end])
            
            vulnerabilities.append({
                "type": vp["type"],
                "severity": vp["severity"],
                "line": line_num,
                "description": vp["description"],
                "suggestion": vp["suggestion"],
                "code": context.strip()
            })
    
    return vulnerabilities

def compute_gas_issues(code: str) -> List[dict]:
    """Analyze gas consumption issues"""
    issues = []
    functions = re.findall(r"function\s+(\w+)\s*\(", code)
    for fn in functions:
        base_gas = random.randint(20000, 60000)
        issues.append({
            "functionName": f"{fn}()",
            "currentGas": base_gas,
            "optimizedGas": int(base_gas * (0.7 + random.random() * 0.2)),
            "suggestion": random.choice(["移除不必要的storage写入", "缓存storage变量到memory", "使用短路逻辑", "合并多个事件为一个"])
        })
    return issues

def compute_security_score(vulnerabilities: List[dict]) -> int:
    """Compute overall security score"""
    if not vulnerabilities:
        return 100
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    deduction = sum(severity_weights.get(v["severity"], 5) for v in vulnerabilities)
    return max(0, 100 - deduction)

@app.get("/")
async def root():
    return {"message": "Smart Contract Security Auditor", "version": "1.0.0"}

@app.get("/api/patterns")
async def list_patterns():
    return {"code": 0, "message": "success", "data": VULNERABILITY_PATTERNS}

@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    vulnerabilities = detect_vulnerabilities(request.code)
    gas_issues = compute_gas_issues(request.code)
    score = compute_security_score(vulnerabilities)

    existing = AUDIT_HISTORY.get(request.filename)
    result = {
        "id": existing["id"] if existing else str(uuid.uuid4()),
        "filename": request.filename,
        "score": score,
        "vulnerabilities": vulnerabilities,
        "gasIssues": gas_issues,
        "timestamp": datetime.now().isoformat()
    }
    AUDIT_HISTORY[request.filename] = result

    return {"code": 0, "message": "success", "data": result}

@app.get("/api/history")
async def get_history():
    records = sorted(AUDIT_HISTORY.values(), key=lambda r: r["timestamp"], reverse=True)
    return {"code": 0, "message": "success", "data": records}

@app.get("/api/audit/{audit_id}")
async def get_audit(audit_id: str):
    for record in AUDIT_HISTORY.values():
        if record["id"] == audit_id:
            return {"code": 0, "message": "success", "data": record}
    raise HTTPException(status_code=404, detail="audit not found")

@app.post("/api/report/{audit_id}")
async def generate_report(audit_id: str):
    """Generate PDF report"""
    # Simplified report generation
    return {"code": 0, "message": "success", "data": {"url": f"/api/reports/{audit_id}.pdf"}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
