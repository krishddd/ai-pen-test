"""
AI Security Pipeline - Report Generator
========================================

Generates comprehensive security reports in Markdown format.
Includes:
- Executive summary
- Detailed findings per category
- Severity ratings
- Evidence snippets
- Remediation recommendations
"""

from datetime import datetime
from typing import Dict, Any, List
import os


class SecurityReporter:
    """Generates security assessment reports in Markdown format."""
    
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
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        severity_map = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵"
        }
        return severity_map.get(severity.upper(), "⚪")
    
    def _truncate_response(self, text: str, max_length: int = 500) -> str:
        """Truncate response text for display."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "... [truncated]"
    
    def add_health_check_result(self, is_healthy: bool, message: str):
        """Add health check result to report."""
        status = "✅ PASSED" if is_healthy else "❌ FAILED"
        self.report_sections.append({
            "title": "Reconnaissance & Health Check",
            "content": f"""
### Target Information
| Property | Value |
|----------|-------|
| Base URL | `{self.target_url}` |
| Model | `{self.model_name}` |
| Status | {status} |
| Details | {message} |
"""
        })
    
    def add_injection_results(self, results: List[Any]):
        """Add injection test results to report."""
        if not results:
            return
        
        vulnerable = [r for r in results if r.success]
        blocked = [r for r in results if r.was_refused]
        errors = [r for r in results if r.error]
        
        content = f"""
### Summary
| Metric | Count |
|--------|-------|
| Total Tests | {len(results)} |
| Vulnerabilities Found | {len(vulnerable)} |
| Attacks Blocked | {len(blocked)} |
| Errors | {len(errors)} |

### Detailed Results
"""
        
        for r in results:
            status = "⚠️ VULNERABLE" if r.success else ("✓ Blocked" if r.was_refused else "○ Not Vulnerable")
            severity = self._get_severity_emoji(r.test.severity)
            
            content += f"""
#### {r.test.test_id}: {r.test.name}
- **Status**: {status}
- **Severity**: {severity} {r.test.severity}
- **Response Time**: {r.response_time:.2f}s
"""
            
            if r.success:
                content += f"""
<details>
<summary>📋 Evidence (Click to expand)</summary>

**Matched Patterns**: `{', '.join(r.matched_patterns)}`

**Response Snippet**:
```
{self._truncate_response(r.response_text)}
```
</details>
"""
                # Add to findings
                self.findings[r.test.severity.lower()].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "Prompt Injection"
                })
            
            if r.error:
                content += f"- **Error**: {r.error}\n"
        
        self.report_sections.append({
            "title": "Prompt Injection Tests",
            "content": content
        })
    
    def add_dos_results(self, results: List[Any]):
        """Add DoS test results to report."""
        if not results:
            return
        
        vulnerable = [r for r in results if r.success]
        
        content = f"""
### Summary
| Metric | Count |
|--------|-------|
| Total Tests | {len(results)} |
| Vulnerabilities Found | {len(vulnerable)} |

### Detailed Results
"""
        
        for r in results:
            status = "⚠️ VULNERABLE" if r.success else "✓ Passed"
            severity = self._get_severity_emoji(r.test.severity)
            
            content += f"""
#### {r.test.test_id}: {r.test.name}
- **Status**: {status}
- **Severity**: {severity} {r.test.severity}
- **Description**: {r.test.description}

<details>
<summary>📊 Test Details</summary>

| Metric | Value |
|--------|-------|
"""
            for key, value in r.details.items():
                content += f"| {key.replace('_', ' ').title()} | {value} |\n"
            
            content += "\n</details>\n"
            
            if r.recommendation:
                content += f"\n> **Recommendation**: {r.recommendation}\n"
            
            if r.success:
                self.findings[r.test.severity.lower()].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "Denial of Service"
                })
        
        self.report_sections.append({
            "title": "Denial of Service Tests",
            "content": content
        })
    
    def add_leakage_results(self, results: List[Any]):
        """Add leakage test results to report."""
        if not results:
            return
        
        vulnerable = [r for r in results if r.success]
        protected = [r for r in results if r.was_protected]
        errors = [r for r in results if r.error]
        
        content = f"""
### Summary
| Metric | Count |
|--------|-------|
| Total Tests | {len(results)} |
| Leakage Detected | {len(vulnerable)} |
| Properly Protected | {len(protected)} |
| Errors | {len(errors)} |

### Detailed Results
"""
        
        for r in results:
            status = "⚠️ LEAKAGE" if r.success else ("✓ Protected" if r.was_protected else "○ Safe")
            severity = self._get_severity_emoji(r.test.severity)
            
            content += f"""
#### {r.test.test_id}: {r.test.name}
- **Status**: {status}
- **Severity**: {severity} {r.test.severity}
- **Response Time**: {r.response_time:.2f}s
"""
            
            if r.success:
                content += f"""
<details>
<summary>📋 Evidence (Click to expand)</summary>

**Matched Patterns**: `{', '.join(r.matched_patterns)}`

**Response Snippet**:
```
{self._truncate_response(r.response_text)}
```
</details>
"""
                self.findings[r.test.severity.lower()].append({
                    "id": r.test.test_id,
                    "name": r.test.name,
                    "category": "Data Leakage"
                })
            
            if r.error:
                content += f"- **Error**: {r.error}\n"
        
        self.report_sections.append({
            "title": "Data Leakage Tests",
            "content": content
        })
    
    def generate_report(self, output_path: str = "security_report.md"):
        """Generate the final security report."""
        
        # Calculate totals
        total_findings = sum(len(f) for f in self.findings.values())
        critical_count = len(self.findings["critical"])
        high_count = len(self.findings["high"])
        medium_count = len(self.findings["medium"])
        low_count = len(self.findings["low"])
        
        # Determine overall risk level
        if critical_count > 0:
            risk_level = "🔴 CRITICAL"
        elif high_count > 0:
            risk_level = "🟠 HIGH"
        elif medium_count > 0:
            risk_level = "🟡 MEDIUM"
        elif low_count > 0:
            risk_level = "🟢 LOW"
        else:
            risk_level = "✅ SECURE"
        
        report = f"""# AI Security Assessment Report

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Target**: `{self.target_url}`  
**Model**: `{self.model_name}`  

---

## Executive Summary

| Risk Level | {risk_level} |
|------------|-------------|
| **Total Findings** | {total_findings} |
| 🔴 Critical | {critical_count} |
| 🟠 High | {high_count} |
| 🟡 Medium | {medium_count} |
| 🟢 Low | {low_count} |

"""
        
        # Add findings summary if any
        if total_findings > 0:
            report += """### Key Findings

| ID | Name | Category | Severity |
|----|------|----------|----------|
"""
            for severity in ["critical", "high", "medium", "low"]:
                for finding in self.findings[severity]:
                    emoji = self._get_severity_emoji(severity)
                    report += f"| {finding['id']} | {finding['name']} | {finding['category']} | {emoji} {severity.upper()} |\n"
            
            report += "\n"
        
        report += "---\n\n## Detailed Test Results\n"
        
        # Add all sections
        for section in self.report_sections:
            report += f"\n### {section['title']}\n"
            report += section['content']
            report += "\n---\n"
        
        # Add recommendations
        report += """
## Recommendations

### Immediate Actions (Critical/High Findings)
1. Review and strengthen system prompts to prevent injection attacks
2. Implement rate limiting and request throttling
3. Add input validation and sanitization
4. Review output filtering mechanisms

### Medium Priority
1. Implement token limits and output length restrictions
2. Add monitoring and alerting for unusual patterns
3. Conduct regular security assessments

### Best Practices
1. Keep model and dependencies updated
2. Implement comprehensive logging
3. Use principle of least privilege
4. Regular penetration testing

---

*Report generated by AI Security Pipeline*
"""
        
        # Write report
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        
        return output_path


def create_reporter(target_url: str, model_name: str) -> SecurityReporter:
    """Factory function to create a reporter instance."""
    return SecurityReporter(target_url, model_name)
