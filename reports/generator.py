"""
AI Security Pipeline v2.0 - Multi-Format Report Generator
==========================================================

Generate security reports in multiple formats:
- Markdown (detailed findings)
- JSON (machine-readable)
- HTML (interactive dashboard)
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import os


class ReportGenerator:
    """Generate security assessment reports in multiple formats."""
    
    def __init__(self, target_url: str, model_name: str):
        self.target_url = target_url
        self.model_name = model_name
        self.report_sections = []
        self.findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        self.raw_data = {}
        self.timestamp = datetime.now().isoformat()
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        return {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵"
        }.get(severity.upper(), "⚪")
    
    def _truncate(self, text: str, max_length: int = 500) -> str:
        """Truncate text for display."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "... [truncated]"
    
    def add_health_check_result(self, is_healthy: bool, message: str):
        """Add health check result."""
        self.raw_data["health_check"] = {
            "healthy": is_healthy,
            "message": message
        }
        
        self.report_sections.append({
            "title": "Reconnaissance & Health Check",
            "content": f"""
### Target Information
| Property | Value |
|----------|-------|
| Base URL | `{self.target_url}` |
| Model | `{self.model_name}` |
| Status | {'✅ HEALTHY' if is_healthy else '❌ UNHEALTHY'} |
| Details | {message} |
"""
        })
    
    def add_injection_results(self, results: List[Any]):
        """Add injection test results."""
        if not results:
            return
        
        self.raw_data["injection"] = [
            {
                "test_id": r.test.test_id,
                "name": r.test.name,
                "success": r.success,
                "severity": r.test.severity,
                "response_time": r.response_time,
            }
            for r in results
        ]
        
        vulnerable = [r for r in results if r.success]
        
        content = f"""
### Summary
- **Total Tests**: {len(results)}
- **Vulnerabilities Found**: {len(vulnerable)}
- **Success Rate**: {len(vulnerable)/len(results)*100:.1f}%

### Results
| ID | Test | Status | Severity |
|----|------|--------|----------|
"""
        for r in results:
            status = "⚠️ VULNERABLE" if r.success else "✓ Blocked"
            emoji = self._get_severity_emoji(r.test.severity)
            content += f"| {r.test.test_id} | {r.test.name} | {status} | {emoji} {r.test.severity} |\n"
            
            if r.success:
                self.findings[r.test.severity.lower()].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "Injection"
                })
        
        self.report_sections.append({"title": "Prompt Injection Tests", "content": content})
    
    def add_dos_results(self, results: List[Any]):
        """Add DoS test results."""
        if not results:
            return
        
        self.raw_data["dos"] = [
            {
                "test_id": r.test.test_id,
                "name": r.test.name,
                "success": r.success,
                "details": r.details,
            }
            for r in results
        ]
        
        vulnerable = [r for r in results if r.success]
        
        content = f"""
### Summary
- **Total Tests**: {len(results)}
- **Vulnerabilities Found**: {len(vulnerable)}

### Results
| ID | Test | Status | Details |
|----|------|--------|---------|
"""
        for r in results:
            status = "⚠️ VULNERABLE" if r.success else "✓ Passed"
            detail = str(r.details.get("failure_rate", "N/A"))
            content += f"| {r.test.test_id} | {r.test.name} | {status} | {detail} |\n"
            
            if r.success:
                self.findings["medium"].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "DoS"
                })
        
        self.report_sections.append({"title": "Denial of Service Tests", "content": content})
    
    def add_leakage_results(self, results: List[Any]):
        """Add leakage test results."""
        if not results:
            return
        
        self.raw_data["leakage"] = [
            {
                "test_id": r.test.test_id,
                "name": r.test.name,
                "success": r.success,
                "severity": r.test.severity,
            }
            for r in results
        ]
        
        vulnerable = [r for r in results if r.success]
        
        content = f"""
### Summary
- **Total Tests**: {len(results)}
- **Leakage Detected**: {len(vulnerable)}

### Results
| ID | Test | Status | Severity |
|----|------|--------|----------|
"""
        for r in results:
            status = "⚠️ LEAKED" if r.success else "✓ Protected"
            emoji = self._get_severity_emoji(r.test.severity)
            content += f"| {r.test.test_id} | {r.test.name} | {status} | {emoji} {r.test.severity} |\n"
            
            if r.success:
                self.findings[r.test.severity.lower()].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "Leakage"
                })
        
        self.report_sections.append({"title": "Data Leakage Tests", "content": content})
    
    def add_poisoning_results(self, results: List[Any]):
        """Add poisoning test results."""
        if not results:
            return
        
        self.raw_data["poisoning"] = [
            {
                "test_id": r.test.test_id,
                "name": r.test.name,
                "success": r.success,
                "persistence_detected": r.persistence_detected,
            }
            for r in results
        ]
        
        vulnerable = [r for r in results if r.success]
        
        content = f"""
### Summary
- **Total Tests**: {len(results)}
- **Persistent Poisoning**: {len(vulnerable)}

### Results
| ID | Test | Status | Persistence |
|----|------|--------|-------------|
"""
        for r in results:
            status = "⚠️ POISONED" if r.success else "✓ Safe"
            persist = "Yes" if r.persistence_detected else "No"
            content += f"| {r.test.test_id} | {r.test.name} | {status} | {persist} |\n"
            
            if r.success:
                self.findings["high"].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "Poisoning"
                })
        
        self.report_sections.append({"title": "Model Poisoning Tests", "content": content})
    
    def add_evasion_results(self, results: List[Any]):
        """Add evasion test results."""
        if not results:
            return
        
        self.raw_data["evasion"] = [
            {
                "test_id": r.test.test_id,
                "name": r.test.name,
                "technique": r.test.technique,
                "success": r.success,
            }
            for r in results
        ]
        
        bypassed = [r for r in results if r.filter_bypassed]
        
        content = f"""
### Summary
- **Total Tests**: {len(results)}
- **Filters Bypassed**: {len(bypassed)}

### Results
| ID | Technique | Status | Matched |
|----|-----------|--------|---------|
"""
        for r in results:
            status = "⚠️ BYPASSED" if r.success else "✓ Blocked"
            matched = ", ".join(r.matched_indicators[:2]) if r.matched_indicators else "None"
            content += f"| {r.test.test_id} | {r.test.technique} | {status} | {matched} |\n"
            
            if r.success:
                self.findings["medium"].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "Evasion"
                })
        
        self.report_sections.append({"title": "Defense Evasion Tests", "content": content})
    
    def add_extraction_results(self, results: List[Any]):
        """Add extraction test results."""
        if not results:
            return
        
        self.raw_data["extraction"] = [
            {
                "test_id": r.test.test_id,
                "name": r.test.name,
                "success": r.success,
                "disclosure_level": r.disclosure_level,
            }
            for r in results
        ]
        
        disclosed = [r for r in results if r.success]
        
        content = f"""
### Summary
- **Total Tests**: {len(results)}
- **Information Disclosed**: {len(disclosed)}

### Results
| ID | Test | Status | Disclosure |
|----|------|--------|------------|
"""
        for r in results:
            status = "⚠️ DISCLOSED" if r.success else "✓ Protected"
            content += f"| {r.test.test_id} | {r.test.name} | {status} | {r.disclosure_level} |\n"
            
            if r.success:
                severity = "high" if r.disclosure_level == "full" else "medium"
                self.findings[severity].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "Extraction"
                })
        
        self.report_sections.append({"title": "Model Extraction Tests", "content": content})
    
    def add_multi_stage_results(self, results: List[Any]):
        """Add multi-stage attack results."""
        if not results:
            return
        
        self.raw_data["multi_stage"] = [
            {
                "chain_id": r.chain.chain_id,
                "name": r.chain.name,
                "success": r.success,
                "stages_completed": r.stages_completed,
                "total_stages": r.total_stages,
                "final_impact": r.final_impact,
            }
            for r in results
        ]
        
        successful = [r for r in results if r.success]
        
        content = f"""
### Summary
- **Total Chains**: {len(results)}
- **Successful Chains**: {len(successful)}

### Results
| ID | Chain | Stages | Impact |
|----|-------|--------|--------|
"""
        for r in results:
            progress = f"{r.stages_completed}/{r.total_stages}"
            content += f"| {r.chain.chain_id} | {r.chain.name} | {progress} | {r.final_impact} |\n"
            
            if r.success:
                severity = "critical" if r.stages_completed == r.total_stages else "high"
                self.findings[severity].append({
                    "id": r.chain.chain_id,
                    "name": r.chain.name,
                    "category": "Multi-Stage"
                })
        
        self.report_sections.append({"title": "Multi-Stage Attack Chains", "content": content})
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-10)."""
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        total = sum(len(f) * weights.get(sev, 0) for sev, f in self.findings.items())
        return min(10.0, total / 5)  # Normalize
    
    def generate_markdown(self) -> str:
        """Generate Markdown report."""
        risk_score = self._calculate_risk_score()
        
        if risk_score >= 8:
            risk_level = "🔴 CRITICAL"
        elif risk_score >= 5:
            risk_level = "🟠 HIGH"
        elif risk_score >= 2:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"
        
        total_findings = sum(len(f) for f in self.findings.values())
        
        report = f"""# AI Security Assessment Report v2.0

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Target**: `{self.target_url}`  
**Model**: `{self.model_name}`

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Risk Level** | {risk_level} |
| **Risk Score** | {risk_score:.1f}/10 |
| **Total Findings** | {total_findings} |
| 🔴 Critical | {len(self.findings['critical'])} |
| 🟠 High | {len(self.findings['high'])} |
| 🟡 Medium | {len(self.findings['medium'])} |
| 🟢 Low | {len(self.findings['low'])} |

"""
        
        if total_findings > 0:
            report += "### Key Findings\n\n| ID | Name | Category | Severity |\n|----|------|----------|----------|\n"
            for sev in ["critical", "high", "medium", "low"]:
                for f in self.findings[sev]:
                    emoji = self._get_severity_emoji(sev)
                    report += f"| {f['id']} | {f['name']} | {f['category']} | {emoji} {sev.upper()} |\n"
        
        report += "\n---\n\n## Detailed Results\n"
        
        for section in self.report_sections:
            report += f"\n### {section['title']}\n{section['content']}\n---\n"
        
        report += """
## Recommendations

### Critical Priority
1. Review and patch all critical and high severity findings
2. Implement robust input validation and output filtering
3. Add rate limiting and request throttling

### Best Practices
1. Regular security assessments
2. Monitor for anomalous patterns
3. Keep model and dependencies updated

---
*Generated by AI Security Pipeline v2.0*
"""
        return report
    
    def generate_json(self) -> str:
        """Generate JSON report."""
        report = {
            "metadata": {
                "timestamp": self.timestamp,
                "target_url": self.target_url,
                "model_name": self.model_name,
                "version": "2.0"
            },
            "summary": {
                "risk_score": self._calculate_risk_score(),
                "total_findings": sum(len(f) for f in self.findings.values()),
                "findings_by_severity": {sev: len(f) for sev, f in self.findings.items()}
            },
            "findings": self.findings,
            "detailed_results": self.raw_data
        }
        return json.dumps(report, indent=2)
    
    def generate_html(self) -> str:
        """Generate HTML dashboard report."""
        risk_score = self._calculate_risk_score()
        total = sum(len(f) for f in self.findings.values())
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Report - {self.target_url}</title>
    <style>
        body {{ font-family: system-ui; max-width: 1200px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #eee; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; }}
        .metric h3 {{ margin: 0; font-size: 2em; }}
        .critical {{ color: #ff6b6b; }} .high {{ color: #ffa502; }} .medium {{ color: #ffd93d; }} .low {{ color: #6bcb77; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #16213e; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI Security Assessment</h1>
        <p>Target: {self.target_url} | Model: {self.model_name}</p>
    </div>
    
    <div class="metric-grid">
        <div class="metric"><h3>{risk_score:.1f}</h3><p>Risk Score</p></div>
        <div class="metric"><h3>{total}</h3><p>Total Findings</p></div>
        <div class="metric critical"><h3>{len(self.findings['critical'])}</h3><p>Critical</p></div>
        <div class="metric high"><h3>{len(self.findings['high'])}</h3><p>High</p></div>
        <div class="metric medium"><h3>{len(self.findings['medium'])}</h3><p>Medium</p></div>
        <div class="metric low"><h3>{len(self.findings['low'])}</h3><p>Low</p></div>
    </div>
    
    <h2>Findings</h2>
    <table>
        <tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th></tr>
        {''.join(f"<tr><td>{f['id']}</td><td>{f['name']}</td><td>{f['category']}</td><td class='{sev}'>{sev.upper()}</td></tr>" for sev in ['critical','high','medium','low'] for f in self.findings[sev])}
    </table>
    
    <footer><p>Generated {datetime.now().strftime("%Y-%m-%d %H:%M")} by AI Security Pipeline v2.0</p></footer>
</body>
</html>"""
    
    def generate_report(self, output_path: str, format: str = "markdown"):
        """Generate report in specified format."""
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        
        if format == "json":
            content = self.generate_json()
        elif format == "html":
            content = self.generate_html()
        else:
            content = self.generate_markdown()
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        return output_path
