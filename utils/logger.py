"""
AI Security Pipeline v2.1 - Detailed Test Logging
===================================================

Provides transparent logging showing:
- Exact payloads sent
- Full LLM responses
- Detection reasoning (why pass/fail)
- Structured log output
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum


class TestStatus(Enum):
    VULNERABLE = "VULNERABLE"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    PARTIAL = "PARTIAL"


@dataclass
class TestLog:
    """Detailed log of a single test."""
    test_id: str
    test_name: str
    category: str
    
    # The attack
    payload: str
    payload_type: str = "text"
    
    # The response
    response: str = ""
    response_time: float = 0.0
    status_code: int = 0
    
    # Detection
    status: TestStatus = TestStatus.ERROR
    detection_reason: str = ""
    matched_indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    # Metadata
    timestamp: str = ""
    severity: str = "MEDIUM"
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        d = asdict(self)
        d["status"] = self.status.value
        return d


class TestLogger:
    """
    Comprehensive test logger that captures and displays all test details.
    
    Provides:
    - Console output with colors
    - JSON log files
    - Markdown reports
    """
    
    def __init__(self, verbose: bool = True, log_dir: str = "./logs"):
        self.verbose = verbose
        self.log_dir = log_dir
        self.logs: List[TestLog] = []
        self.current_category = ""
        
        os.makedirs(log_dir, exist_ok=True)
    
    def start_category(self, category: str):
        """Start logging a new test category."""
        self.current_category = category
        if self.verbose:
            print(f"\n{'='*70}")
            print(f"  {category.upper()} TESTS")
            print(f"{'='*70}")
    
    def log_test(
        self,
        test_id: str,
        test_name: str,
        payload: str,
        response: str,
        response_time: float,
        status: TestStatus,
        detection_reason: str,
        matched_indicators: List[str] = None,
        confidence: float = 0.0,
        severity: str = "MEDIUM",
        status_code: int = 200
    ) -> TestLog:
        """Log a complete test with all details."""
        log = TestLog(
            test_id=test_id,
            test_name=test_name,
            category=self.current_category,
            payload=payload,
            response=response,
            response_time=response_time,
            status_code=status_code,
            status=status,
            detection_reason=detection_reason,
            matched_indicators=matched_indicators or [],
            confidence=confidence,
            severity=severity
        )
        
        self.logs.append(log)
        
        if self.verbose:
            self._print_test_log(log)
        
        return log
    
    def _print_test_log(self, log: TestLog):
        """Print detailed test log to console."""
        # Status emoji and color
        status_display = {
            TestStatus.VULNERABLE: "🔴 VULNERABLE",
            TestStatus.BLOCKED: "✅ BLOCKED",
            TestStatus.ERROR: "⚠️  ERROR",
            TestStatus.PARTIAL: "🟡 PARTIAL"
        }
        
        print(f"\n┌─ {log.test_id}: {log.test_name}")
        print(f"│  Status: {status_display.get(log.status, log.status.value)}")
        print(f"│  Response Time: {log.response_time:.2f}s")
        print(f"│")
        
        # Show truncated payload
        payload_preview = log.payload[:200].replace('\n', ' ')
        if len(log.payload) > 200:
            payload_preview += "..."
        print(f"│  📤 PAYLOAD:")
        print(f"│     {payload_preview}")
        print(f"│")
        
        # Show truncated response
        response_preview = log.response[:300].replace('\n', ' ')
        if len(log.response) > 300:
            response_preview += "..."
        print(f"│  📥 RESPONSE:")
        print(f"│     {response_preview}")
        print(f"│")
        
        # Show detection reasoning
        print(f"│  🔍 DETECTION:")
        print(f"│     Reason: {log.detection_reason}")
        if log.matched_indicators:
            print(f"│     Matched: {', '.join(log.matched_indicators[:5])}")
        print(f"│     Confidence: {log.confidence:.0%}")
        print(f"└{'─'*60}")
    
    def log_error(self, test_id: str, test_name: str, payload: str, error: str):
        """Log a test error."""
        return self.log_test(
            test_id=test_id,
            test_name=test_name,
            payload=payload,
            response=f"ERROR: {error}",
            response_time=0.0,
            status=TestStatus.ERROR,
            detection_reason=f"Request failed: {error}",
            status_code=0
        )
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        total = len(self.logs)
        vulnerable = sum(1 for l in self.logs if l.status == TestStatus.VULNERABLE)
        blocked = sum(1 for l in self.logs if l.status == TestStatus.BLOCKED)
        errors = sum(1 for l in self.logs if l.status == TestStatus.ERROR)
        
        return {
            "total_tests": total,
            "vulnerable": vulnerable,
            "blocked": blocked,
            "errors": errors,
            "vulnerability_rate": f"{vulnerable/max(1,total)*100:.1f}%"
        }
    
    def print_summary(self):
        """Print final summary."""
        summary = self.get_summary()
        
        print(f"\n{'='*70}")
        print(f"  SUMMARY")
        print(f"{'='*70}")
        print(f"  Total Tests:    {summary['total_tests']}")
        print(f"  🔴 Vulnerable:  {summary['vulnerable']}")
        print(f"  ✅ Blocked:     {summary['blocked']}")
        print(f"  ⚠️  Errors:      {summary['errors']}")
        print(f"  Vuln Rate:      {summary['vulnerability_rate']}")
        print(f"{'='*70}\n")
    
    def save_json_log(self, filename: str = None) -> str:
        """Save all logs to JSON file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.log_dir, f"test_logs_{timestamp}.json")
        
        data = {
            "timestamp": datetime.now().isoformat(),
            "summary": self.get_summary(),
            "tests": [log.to_dict() for log in self.logs]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        if self.verbose:
            print(f"\n📁 Logs saved to: {filename}")
        
        return filename
    
    def save_markdown_log(self, filename: str = None) -> str:
        """Save all logs to Markdown file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.log_dir, f"test_logs_{timestamp}.md")
        
        summary = self.get_summary()
        
        lines = [
            "# Security Test Detailed Logs",
            f"\nGenerated: {datetime.now().isoformat()}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Tests | {summary['total_tests']} |",
            f"| Vulnerable | {summary['vulnerable']} |",
            f"| Blocked | {summary['blocked']} |",
            f"| Errors | {summary['errors']} |",
            f"| Vulnerability Rate | {summary['vulnerability_rate']} |",
            "",
            "---",
            "",
            "## Detailed Test Logs",
            ""
        ]
        
        # Group by category
        categories = {}
        for log in self.logs:
            if log.category not in categories:
                categories[log.category] = []
            categories[log.category].append(log)
        
        for category, logs in categories.items():
            lines.append(f"### {category}")
            lines.append("")
            
            for log in logs:
                status_icon = {
                    TestStatus.VULNERABLE: "🔴",
                    TestStatus.BLOCKED: "✅",
                    TestStatus.ERROR: "⚠️",
                    TestStatus.PARTIAL: "🟡"
                }.get(log.status, "❓")
                
                lines.extend([
                    f"#### {status_icon} {log.test_id}: {log.test_name}",
                    "",
                    f"**Status:** {log.status.value} | **Severity:** {log.severity} | **Time:** {log.response_time:.2f}s",
                    "",
                    "**Payload Sent:**",
                    "```",
                    log.payload[:500] + ("..." if len(log.payload) > 500 else ""),
                    "```",
                    "",
                    "**Response Received:**",
                    "```",
                    log.response[:500] + ("..." if len(log.response) > 500 else ""),
                    "```",
                    "",
                    "**Detection Analysis:**",
                    f"- **Reason:** {log.detection_reason}",
                    f"- **Matched Indicators:** {', '.join(log.matched_indicators) if log.matched_indicators else 'None'}",
                    f"- **Confidence:** {log.confidence:.0%}",
                    "",
                    "---",
                    ""
                ])
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        if self.verbose:
            print(f"📁 Markdown log saved to: {filename}")
        
        return filename
    
    def get_vulnerable_tests(self) -> List[TestLog]:
        """Get all tests that found vulnerabilities."""
        return [l for l in self.logs if l.status == TestStatus.VULNERABLE]
    
    def get_logs_by_category(self, category: str) -> List[TestLog]:
        """Get all logs for a specific category."""
        return [l for l in self.logs if l.category == category]


# Global logger instance
_logger: Optional[TestLogger] = None


def get_logger(verbose: bool = True) -> TestLogger:
    """Get or create global logger instance."""
    global _logger
    if _logger is None:
        _logger = TestLogger(verbose=verbose)
    return _logger


def reset_logger():
    """Reset the global logger."""
    global _logger
    _logger = None


def log_test_result(
    test_id: str,
    test_name: str,
    category: str,
    payload: str,
    response: str,
    response_time: float,
    is_vulnerable: bool,
    detection_reason: str,
    matched_indicators: List[str] = None,
    confidence: float = 0.0
):
    """Convenience function to log a test result."""
    logger = get_logger()
    logger.current_category = category
    
    status = TestStatus.VULNERABLE if is_vulnerable else TestStatus.BLOCKED
    
    logger.log_test(
        test_id=test_id,
        test_name=test_name,
        payload=payload,
        response=response,
        response_time=response_time,
        status=status,
        detection_reason=detection_reason,
        matched_indicators=matched_indicators,
        confidence=confidence
    )
