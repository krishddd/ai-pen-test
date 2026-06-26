"""
AI Security Pipeline v2.0 - FastAPI REST API
=============================================

RESTful API for LLM security testing with:
- Configuration management
- Attack execution endpoints
- Report generation and retrieval
- Engagement lifecycle management (create, resume, diff)
"""

import os
import sys
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse

from client import LLMClient, ClientConfig
from scanner import SecurityScanner, ScanConfig
from attacks import injection, dos, leakage, poisoning, evasion, extraction, multi_stage
from reports.generator import ReportGenerator


# ============================================================================
# Pydantic Models
# ============================================================================

class TargetConfig(BaseModel):
    """Target LLM configuration."""
    base_url: str = Field(default="http://213.163.75.246:50049", description="LLM endpoint URL")
    model: str = Field(default="qwen2.5:7b", description="Model name")
    api_key: str = Field(default="", description="API key for authentication")
    timeout: int = Field(default=30, ge=5, le=120, description="Request timeout in seconds")


class ScannerConfig(BaseModel):
    """Scanner configuration."""
    concurrency: int = Field(default=5, ge=1, le=20)
    concurrent_requests: int = Field(default=30, ge=10, le=100, description="DoS concurrent requests")
    payload_size: int = Field(default=10000, ge=1000, le=100000, description="DoS payload size")


class PipelineConfig(BaseModel):
    """Full pipeline configuration."""
    target: TargetConfig = Field(default_factory=TargetConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    report_formats: List[str] = Field(default=["markdown", "json"])


class AttackRequest(BaseModel):
    """Request to run a specific attack."""
    verbose: bool = Field(default=False, description="Print progress to console")
    include_logs: bool = Field(default=True, description="Include detailed test logs in response")


class ScanRequest(BaseModel):
    """Request to run multiple attacks."""
    attacks: List[str] = Field(
        default=["injection", "dos", "leakage"],
        description="Attack categories to run"
    )
    parallel: bool = Field(default=False)
    verbose: bool = Field(default=False)
    include_logs: bool = Field(default=True, description="Include detailed test logs in response")


class TestLogEntry(BaseModel):
    """Detailed log of a single test."""
    test_id: str
    test_name: str
    payload: str
    response: str
    response_time: float
    status: str  # VULNERABLE, BLOCKED, ERROR
    detection_reason: str
    matched_indicators: List[str] = []
    confidence: float = 0.0
    severity: str = "MEDIUM"


class AttackResult(BaseModel):
    """Result of an attack execution."""
    attack_type: str
    status: str
    vulnerabilities_found: int
    total_tests: int
    execution_time: float
    details: Dict[str, Any] = {}
    test_logs: List[TestLogEntry] = Field(default=[], description="Detailed logs for each test")


class ScanResult(BaseModel):
    """Result of a full scan."""
    scan_id: str
    status: str
    target: str
    model: str
    attacks_run: List[str]
    total_vulnerabilities: int
    results: Dict[str, AttackResult]
    report_paths: Dict[str, str]
    timestamp: str


# ============================================================================
# Global State
# ============================================================================

class PipelineState:
    """Global state for the pipeline."""
    
    def __init__(self):
        self.config: Optional[PipelineConfig] = None
        self.client: Optional[LLMClient] = None
        self.scanner: Optional[SecurityScanner] = None
        self.scans: Dict[str, ScanResult] = {}
        self.reports_dir = "./api_reports"
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def is_configured(self) -> bool:
        return self.config is not None and self.client is not None
    
    def configure(self, config: PipelineConfig):
        self.config = config
        
        # Create client
        client_config = ClientConfig(
            base_url=config.target.base_url,
            model=config.target.model,
            api_key=config.target.api_key,
            timeout=config.target.timeout
        )
        self.client = LLMClient(client_config)
        
        # Create scanner
        scan_config = ScanConfig(
            base_url=config.target.base_url,
            model=config.target.model,
            api_key=config.target.api_key,
            timeout=config.target.timeout,
            concurrency=config.scanner.concurrency,
            concurrent_requests=config.scanner.concurrent_requests,
            payload_size=config.scanner.payload_size,
            report_formats=config.report_formats,
            verbose=False,
            progress_bar=False
        )
        self.scanner = SecurityScanner(scan_config)


state = PipelineState()


# ============================================================================
# FastAPI Application
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    print("🚀 AI Security Pipeline API starting...")
    yield
    print("👋 AI Security Pipeline API shutting down...")


app = FastAPI(
    title="AI Security Pipeline API",
    description="REST API for LLM penetration testing",
    version="2.0.0",
    lifespan=lifespan
)


# ============================================================================
# Configuration Endpoints
# ============================================================================

@app.get("/", tags=["Info"])
async def root():
    """API info and status."""
    return {
        "name": "AI Security Pipeline API",
        "version": "2.0.0",
        "status": "configured" if state.is_configured() else "not_configured",
        "endpoints": {
            "config": "/config",
            "health_check": "/health",
            "attacks": "/attacks/{attack_type}",
            "scan": "/scan",
            "reports": "/reports"
        }
    }


@app.post("/config", tags=["Configuration"])
async def set_configuration(config: PipelineConfig):
    """
    Configure the pipeline with target and scanner settings.
    This must be called before running any attacks.
    """
    try:
        state.configure(config)
        return {
            "status": "configured",
            "target": {
                "base_url": config.target.base_url,
                "model": config.target.model,
                "has_api_key": bool(config.target.api_key)
            },
            "scanner": config.scanner.model_dump(),
            "report_formats": config.report_formats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/config", tags=["Configuration"])
async def get_configuration():
    """Get current pipeline configuration."""
    if not state.is_configured():
        raise HTTPException(status_code=400, detail="Pipeline not configured. POST to /config first.")
    
    return {
        "target": {
            "base_url": state.config.target.base_url,
            "model": state.config.target.model,
            "has_api_key": bool(state.config.target.api_key),
            "timeout": state.config.target.timeout
        },
        "scanner": state.config.scanner.model_dump(),
        "report_formats": state.config.report_formats
    }


@app.get("/health", tags=["Configuration"])
async def health_check():
    """Run health check against configured target."""
    if not state.is_configured():
        raise HTTPException(status_code=400, detail="Pipeline not configured. POST to /config first.")
    
    is_healthy, message = state.client.health_check()
    metrics = state.client.get_metrics()
    
    return {
        "healthy": is_healthy,
        "message": message,
        "circuit_breaker": metrics["circuit_breaker_state"],
        "metrics": {
            "total_requests": metrics["total_requests"],
            "success_rate": metrics["success_rate"]
        }
    }


# ============================================================================
# Attack Endpoints
# ============================================================================

def require_configured():
    """Check if pipeline is configured."""
    if not state.is_configured():
        raise HTTPException(status_code=400, detail="Pipeline not configured. POST to /config first.")


def build_leakage_logs(results) -> List[TestLogEntry]:
    """Build detailed logs for leakage tests."""
    logs = []
    for r in results:
        # LeakageResult has: test, success, response_text, matched_patterns, was_protected, response_time, error
        if r.error:
            status = "ERROR"
            reason = f"Request failed: {r.error}"
        elif r.success:
            status = "VULNERABLE"
            reason = f"Leaked patterns: {', '.join(r.matched_patterns[:3])}" if r.matched_patterns else "Data leakage detected"
        else:
            status = "BLOCKED"
            reason = "Protected - no leakage indicators found"
        
        logs.append(TestLogEntry(
            test_id=r.test.test_id,
            test_name=r.test.name,
            payload=r.test.payload,
            response=r.response_text[:1000] if r.response_text else "No response",
            response_time=r.response_time,
            status=status,
            detection_reason=reason,
            matched_indicators=r.matched_patterns if r.matched_patterns else [],
            severity=r.test.severity
        ))
    return logs


def build_poisoning_logs(results) -> List[TestLogEntry]:
    """Build detailed logs for poisoning tests."""
    logs = []
    for r in results:
        # PoisoningResult has: test, success, injection_responses, verification_response, matched_indicators, persistence_detected, response_time, error
        if r.error:
            status = "ERROR"
            reason = f"Request failed: {r.error}"
        elif r.success:
            status = "VULNERABLE"
            reason = f"Poisoning persisted. Matched: {', '.join(r.matched_indicators[:3])}" if r.matched_indicators else "Behavior manipulation detected"
        else:
            status = "BLOCKED"
            reason = "No persistent behavior modification"
        
        # Combine all poison payloads
        all_payloads = "\n".join(r.test.payloads[:3])
        
        logs.append(TestLogEntry(
            test_id=r.test.test_id,
            test_name=r.test.name,
            payload=all_payloads[:500],
            response=r.verification_response[:1000] if r.verification_response else "No response",
            response_time=r.response_time,
            status=status,
            detection_reason=reason,
            matched_indicators=r.matched_indicators if r.matched_indicators else [],
            severity=r.test.severity
        ))
    return logs


def build_evasion_logs(results) -> List[TestLogEntry]:
    """Build detailed logs for evasion tests."""
    logs = []
    for r in results:
        # EvasionResult has: test, success, response_text, matched_indicators, filter_bypassed, response_time, error
        if r.error:
            status = "ERROR"
            reason = f"Request failed: {r.error}"
        elif r.success:
            status = "VULNERABLE"
            reason = f"Filter bypassed using {r.test.technique}. Matched: {', '.join(r.matched_indicators[:3])}"
        else:
            status = "BLOCKED"
            reason = f"Filter blocked {r.test.technique} encoded payload"
        
        logs.append(TestLogEntry(
            test_id=r.test.test_id,
            test_name=r.test.name,
            payload=r.test.encoded_payload[:500],
            response=r.response_text[:1000] if r.response_text else "No response",
            response_time=r.response_time,
            status=status,
            detection_reason=reason,
            matched_indicators=r.matched_indicators if r.matched_indicators else [],
            severity="MEDIUM"
        ))
    return logs


def build_extraction_logs(results) -> List[TestLogEntry]:
    """Build detailed logs for extraction tests."""
    logs = []
    for r in results:
        # ExtractionResult has: test, success, extracted_info, disclosure_level, response_time, responses, error
        if hasattr(r, 'error') and r.error:
            status = "ERROR"
            reason = f"Request failed: {r.error}"
        elif r.success:
            status = "VULNERABLE"
            reason = f"Disclosure level: {r.disclosure_level}. Extracted: {list(r.extracted_info.keys())[:3]}"
        else:
            status = "BLOCKED"
            reason = "No sensitive information disclosed"
        
        # Combine probes and responses
        all_probes = "\n".join(r.test.probes[:3])
        all_responses = "\n---\n".join(r.responses[:3]) if r.responses else "No responses"
        
        logs.append(TestLogEntry(
            test_id=r.test.test_id,
            test_name=r.test.name,
            payload=all_probes[:500],
            response=all_responses[:1000],
            response_time=r.response_time,
            status=status,
            detection_reason=reason,
            matched_indicators=list(r.extracted_info.keys()) if r.extracted_info else [],
            severity=r.test.severity
        ))
    return logs


def build_multi_stage_logs(results) -> List[TestLogEntry]:
    """Build detailed logs for multi-stage attacks."""
    logs = []
    for r in results:
        # ChainResult has: chain, success, stages_completed, total_stages, stage_results, final_impact, total_time
        if r.stages_completed == r.total_stages:
            status = "VULNERABLE"
            reason = f"Full chain completed! {r.stages_completed}/{r.total_stages} stages passed"
        elif r.stages_completed > 0:
            status = "VULNERABLE"
            reason = f"Partial success. {r.stages_completed}/{r.total_stages} stages passed"
        else:
            status = "BLOCKED"
            reason = "Attack chain blocked at first stage"
        
        # Combine all stage prompts
        all_prompts = "\n---STAGE---\n".join([s.prompt[:200] for s in r.chain.stages[:3]])
        all_responses = "\n---RESPONSE---\n".join([sr.response[:200] for sr in r.stage_results[:3]])
        
        logs.append(TestLogEntry(
            test_id=r.chain.chain_id,
            test_name=r.chain.name,
            payload=all_prompts[:1000],
            response=all_responses[:1000] if all_responses else "No responses",
            response_time=r.total_time,
            status=status,
            detection_reason=reason,
            confidence=r.stages_completed / max(1, r.total_stages),
            severity="CRITICAL" if r.stages_completed == r.total_stages else "HIGH"
        ))
    return logs


def build_dos_logs(results) -> List[TestLogEntry]:
    """Build detailed logs for DoS tests."""
    logs = []
    for r in results:
        # DoSResult has: test, success, details (dict), recommendation
        details_str = str(r.details) if r.details else ""
        
        if r.success:
            status = "VULNERABLE"
            reason = details_str[:200] if details_str else "DoS vulnerability detected"
        else:
            status = "BLOCKED"
            reason = "System handled load correctly"
        
        logs.append(TestLogEntry(
            test_id=r.test.test_id,
            test_name=r.test.name,
            payload=f"[{r.test.test_id}] {r.test.description}",
            response=details_str[:500] if details_str else "Test completed",
            response_time=0.0,  # DoS tests don't track individual response time
            status=status,
            detection_reason=reason,
            severity=r.test.severity
        ))
    return logs


@app.post("/attacks/injection", tags=["Attacks"])
async def run_injection_attack(request: AttackRequest = AttackRequest()):
    """Run prompt injection tests with detailed logs."""
    require_configured()
    
    import time
    start = time.time()
    
    results = injection.run_injection_tests(state.client, request.verbose)
    summary = injection.get_test_summary(results)
    
    # Build detailed test logs
    test_logs = []
    if request.include_logs:
        for r in results:
            # Determine status and reason
            if r.error:
                status = "ERROR"
                reason = f"Request failed: {r.error}"
            elif r.success:
                status = "VULNERABLE"
                reason = f"Matched patterns: {', '.join(r.matched_patterns[:3])}" if r.matched_patterns else "Success indicators detected"
            elif r.was_refused:
                status = "BLOCKED"
                reason = "LLM explicitly refused the request"
            else:
                status = "BLOCKED"
                reason = "No success patterns matched"
            
            test_logs.append(TestLogEntry(
                test_id=r.test.test_id,
                test_name=r.test.name,
                payload=r.test.payload,
                response=r.response_text[:1000] if r.response_text else r.error or "No response",
                response_time=r.response_time,
                status=status,
                detection_reason=reason,
                matched_indicators=r.matched_patterns,
                confidence=min(1.0, len(r.matched_patterns) * 0.3) if r.matched_patterns else 0.0,
                severity=r.test.severity
            ))
    
    return AttackResult(
        attack_type="injection",
        status="completed",
        vulnerabilities_found=summary["vulnerabilities_found"],
        total_tests=summary["total_tests"],
        execution_time=time.time() - start,
        details=summary,
        test_logs=test_logs
    )


@app.post("/attacks/dos", tags=["Attacks"])
async def run_dos_attack(request: AttackRequest = AttackRequest()):
    """Run denial of service tests with detailed logs."""
    require_configured()
    
    import time
    start = time.time()
    
    results = dos.run_dos_tests(
        state.client,
        state.config.scanner.concurrent_requests,
        state.config.scanner.payload_size,
        request.verbose
    )
    summary = dos.get_test_summary(results)
    test_logs = build_dos_logs(results) if request.include_logs else []
    
    return AttackResult(
        attack_type="dos",
        status="completed",
        vulnerabilities_found=summary["vulnerabilities_found"],
        total_tests=summary["total_tests"],
        execution_time=time.time() - start,
        details=summary,
        test_logs=test_logs
    )


@app.post("/attacks/leakage", tags=["Attacks"])
async def run_leakage_attack(request: AttackRequest = AttackRequest()):
    """Run data leakage tests with detailed logs."""
    require_configured()
    
    import time
    start = time.time()
    
    results = leakage.run_leakage_tests(state.client, request.verbose)
    summary = leakage.get_test_summary(results)
    test_logs = build_leakage_logs(results) if request.include_logs else []
    
    return AttackResult(
        attack_type="leakage",
        status="completed",
        vulnerabilities_found=summary["vulnerabilities_found"],
        total_tests=summary["total_tests"],
        execution_time=time.time() - start,
        details=summary,
        test_logs=test_logs
    )


@app.post("/attacks/poisoning", tags=["Attacks"])
async def run_poisoning_attack(request: AttackRequest = AttackRequest()):
    """Run model poisoning tests with detailed logs."""
    require_configured()
    
    import time
    start = time.time()
    
    results = poisoning.run_poisoning_tests(state.client, request.verbose)
    summary = poisoning.get_test_summary(results)
    test_logs = build_poisoning_logs(results) if request.include_logs else []
    
    return AttackResult(
        attack_type="poisoning",
        status="completed",
        vulnerabilities_found=summary["vulnerabilities_found"],
        total_tests=summary["total_tests"],
        execution_time=time.time() - start,
        details=summary,
        test_logs=test_logs
    )


@app.post("/attacks/evasion", tags=["Attacks"])
async def run_evasion_attack(request: AttackRequest = AttackRequest()):
    """Run defense evasion tests with detailed logs."""
    require_configured()
    
    import time
    start = time.time()
    
    results = evasion.run_evasion_tests(state.client, request.verbose)
    summary = evasion.get_test_summary(results)
    test_logs = build_evasion_logs(results) if request.include_logs else []
    
    return AttackResult(
        attack_type="evasion",
        status="completed",
        vulnerabilities_found=summary["filters_bypassed"],
        total_tests=summary["total_tests"],
        execution_time=time.time() - start,
        details=summary,
        test_logs=test_logs
    )


@app.post("/attacks/extraction", tags=["Attacks"])
async def run_extraction_attack(request: AttackRequest = AttackRequest()):
    """Run model extraction tests with detailed logs."""
    require_configured()
    
    import time
    start = time.time()
    
    results = extraction.run_extraction_tests(state.client, request.verbose)
    summary = extraction.get_test_summary(results)
    test_logs = build_extraction_logs(results) if request.include_logs else []
    
    return AttackResult(
        attack_type="extraction",
        status="completed",
        vulnerabilities_found=summary["information_disclosed"],
        total_tests=summary["total_tests"],
        execution_time=time.time() - start,
        details=summary,
        test_logs=test_logs
    )


@app.post("/attacks/multi_stage", tags=["Attacks"])
async def run_multi_stage_attack(request: AttackRequest = AttackRequest()):
    """Run multi-stage attack chains with detailed logs."""
    require_configured()
    
    import time
    start = time.time()
    
    results = multi_stage.run_multi_stage_tests(state.client, request.verbose)
    summary = multi_stage.get_test_summary(results)
    test_logs = build_multi_stage_logs(results) if request.include_logs else []
    
    return AttackResult(
        attack_type="multi_stage",
        status="completed",
        vulnerabilities_found=summary["chains_with_success"],
        total_tests=summary["total_chains"],
        execution_time=time.time() - start,
        details=summary,
        test_logs=test_logs
    )


# ============================================================================
# Full Scan Endpoint
# ============================================================================

@app.post("/scan", tags=["Scan"])
async def run_full_scan(request: ScanRequest = ScanRequest()):
    """
    Run a full security scan with selected attack categories.
    Generates and saves reports automatically.
    """
    require_configured()
    
    import time
    start = time.time()
    scan_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now().isoformat()
    
    # Map attack names to functions
    attack_funcs = {
        "injection": (injection.run_injection_tests, injection.get_test_summary, "vulnerabilities_found"),
        "dos": (lambda c, v: dos.run_dos_tests(c, state.config.scanner.concurrent_requests, state.config.scanner.payload_size, v), dos.get_test_summary, "vulnerabilities_found"),
        "leakage": (leakage.run_leakage_tests, leakage.get_test_summary, "vulnerabilities_found"),
        "poisoning": (poisoning.run_poisoning_tests, poisoning.get_test_summary, "vulnerabilities_found"),
        "evasion": (evasion.run_evasion_tests, evasion.get_test_summary, "filters_bypassed"),
        "extraction": (extraction.run_extraction_tests, extraction.get_test_summary, "information_disclosed"),
        "multi_stage": (multi_stage.run_multi_stage_tests, multi_stage.get_test_summary, "chains_with_success"),
    }
    
    results = {}
    total_vulns = 0
    reporter = ReportGenerator(state.config.target.base_url, state.config.target.model)
    
    # Run health check first
    is_healthy, message = state.client.health_check()
    reporter.add_health_check_result(is_healthy, message)
    
    # Run selected attacks
    for attack_name in request.attacks:
        if attack_name not in attack_funcs:
            continue
        
        run_func, summary_func, vuln_key = attack_funcs[attack_name]
        attack_start = time.time()
        
        try:
            attack_results = run_func(state.client, request.verbose)
            summary = summary_func(attack_results)
            
            vuln_count = summary.get(vuln_key, 0)
            total_tests = summary.get("total_tests", summary.get("total_chains", 0))
            
            results[attack_name] = AttackResult(
                attack_type=attack_name,
                status="completed",
                vulnerabilities_found=vuln_count,
                total_tests=total_tests,
                execution_time=time.time() - attack_start,
                details=summary
            )
            
            total_vulns += vuln_count
            
            # Add to reporter
            if attack_name == "injection":
                reporter.add_injection_results(attack_results)
            elif attack_name == "dos":
                reporter.add_dos_results(attack_results)
            elif attack_name == "leakage":
                reporter.add_leakage_results(attack_results)
            elif attack_name == "poisoning":
                reporter.add_poisoning_results(attack_results)
            elif attack_name == "evasion":
                reporter.add_evasion_results(attack_results)
            elif attack_name == "extraction":
                reporter.add_extraction_results(attack_results)
            elif attack_name == "multi_stage":
                reporter.add_multi_stage_results(attack_results)
                
        except Exception as e:
            results[attack_name] = AttackResult(
                attack_type=attack_name,
                status="failed",
                vulnerabilities_found=0,
                total_tests=0,
                execution_time=time.time() - attack_start,
                details={"error": str(e)}
            )
    
    # Generate and save reports
    report_paths = {}
    for fmt in state.config.report_formats:
        ext = "md" if fmt == "markdown" else fmt
        path = os.path.join(state.reports_dir, f"scan_{scan_id}.{ext}")
        reporter.generate_report(path, fmt)
        report_paths[fmt] = path
    
    # Create scan result
    scan_result = ScanResult(
        scan_id=scan_id,
        status="completed",
        target=state.config.target.base_url,
        model=state.config.target.model,
        attacks_run=request.attacks,
        total_vulnerabilities=total_vulns,
        results={k: v.model_dump() for k, v in results.items()},
        report_paths=report_paths,
        timestamp=timestamp
    )
    
    # Store scan
    state.scans[scan_id] = scan_result
    
    return scan_result


# ============================================================================
# Report Endpoints
# ============================================================================

@app.get("/reports", tags=["Reports"])
async def list_reports():
    """List all saved scan reports."""
    reports = []
    
    for scan_id, scan in state.scans.items():
        reports.append({
            "scan_id": scan_id,
            "timestamp": scan.timestamp,
            "target": scan.target,
            "vulnerabilities": scan.total_vulnerabilities,
            "formats": list(scan.report_paths.keys())
        })
    
    # Also list files in reports directory
    files = []
    if os.path.exists(state.reports_dir):
        for f in os.listdir(state.reports_dir):
            path = os.path.join(state.reports_dir, f)
            files.append({
                "filename": f,
                "size": os.path.getsize(path),
                "path": path
            })
    
    return {"scans": reports, "files": files}


@app.get("/reports/{scan_id}", tags=["Reports"])
async def get_report(scan_id: str, format: str = "json"):
    """Get a specific scan report."""
    if scan_id not in state.scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    scan = state.scans[scan_id]
    
    if format in scan.report_paths:
        path = scan.report_paths[format]
        if os.path.exists(path):
            return FileResponse(path, filename=os.path.basename(path))
    
    # Return scan data as JSON
    return scan


@app.get("/reports/{scan_id}/download/{format}", tags=["Reports"])
async def download_report(scan_id: str, format: str = "markdown"):
    """Download a report file."""
    if scan_id not in state.scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    scan = state.scans[scan_id]
    
    if format not in scan.report_paths:
        raise HTTPException(status_code=404, detail=f"Format {format} not available")
    
    path = scan.report_paths[format]
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report file not found")
    
    return FileResponse(
        path,
        filename=os.path.basename(path),
        media_type="application/octet-stream"
    )


# ============================================================================
# Metrics Endpoint
# ============================================================================

@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    """Get client and pipeline metrics."""
    if not state.is_configured():
        raise HTTPException(status_code=400, detail="Pipeline not configured")
    
    client_metrics = state.client.get_metrics()
    
    return {
        "client": client_metrics,
        "scans_completed": len(state.scans),
        "total_vulnerabilities_found": sum(s.total_vulnerabilities for s in state.scans.values())
    }


# ============================================================================
# Run with Uvicorn
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
