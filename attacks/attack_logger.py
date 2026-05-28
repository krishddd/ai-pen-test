"""
AI Security Pipeline v2.1 - Attack Logging Helper
===================================================

Helper functions to integrate detailed logging into all attack modules.
"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import time


@dataclass
class AttackResult:
    """Generic attack result with full transparency."""
    test_id: str
    test_name: str
    category: str
    payload: str
    response: str
    response_time: float
    is_vulnerable: bool
    is_refused: bool
    detection_reason: str
    matched_indicators: List[str]
    confidence: float
    severity: str
    error: str = ""


class AttackLogger:
    """
    Unified attack logger for all attack modules.
    
    Usage:
        logger = AttackLogger("Injection", verbose=True)
        
        for test in tests:
            response = client.generate(test.payload)
            logger.log_result(
                test_id=test.id,
                test_name=test.name,
                payload=test.payload,
                response=response.text,
                is_vulnerable=True/False,
                ...
            )
        
        logger.finish()  # Prints summary and saves logs
    """
    
    def __init__(self, category: str, verbose: bool = False):
        self.category = category
        self.verbose = verbose
        self.results: List[AttackResult] = []
        self._logger = None
        
        if verbose:
            self._init_logger()
    
    def _init_logger(self):
        """Initialize the detailed logger."""
        try:
            from utils.logger import TestLogger
            self._logger = TestLogger(verbose=True)
            self._logger.start_category(self.category)
        except ImportError:
            self._logger = None
            print(f"\n{'='*70}")
            print(f"  {self.category.upper()} TESTS (Verbose Mode)")
            print(f"{'='*70}")
    
    def log_result(
        self,
        test_id: str,
        test_name: str,
        payload: str,
        response: str,
        response_time: float,
        is_vulnerable: bool,
        is_refused: bool = False,
        detection_reason: str = "",
        matched_indicators: List[str] = None,
        confidence: float = 0.0,
        severity: str = "MEDIUM",
        error: str = ""
    ) -> AttackResult:
        """Log a single test result."""
        result = AttackResult(
            test_id=test_id,
            test_name=test_name,
            category=self.category,
            payload=payload,
            response=response,
            response_time=response_time,
            is_vulnerable=is_vulnerable,
            is_refused=is_refused,
            detection_reason=detection_reason,
            matched_indicators=matched_indicators or [],
            confidence=confidence,
            severity=severity,
            error=error
        )
        
        self.results.append(result)
        
        # Log with detailed logger if available
        if self._logger:
            from utils.logger import TestStatus
            
            if error:
                status = TestStatus.ERROR
            elif is_vulnerable:
                status = TestStatus.VULNERABLE
            else:
                status = TestStatus.BLOCKED
            
            self._logger.log_test(
                test_id=test_id,
                test_name=test_name,
                payload=payload,
                response=response if not error else f"ERROR: {error}",
                response_time=response_time,
                status=status,
                detection_reason=detection_reason,
                matched_indicators=matched_indicators or [],
                confidence=confidence,
                severity=severity
            )
        elif self.verbose:
            # Fallback to simple console output
            self._print_simple(result)
        
        return result
    
    def _print_simple(self, result: AttackResult):
        """Simple console output when logger not available."""
        status = "🔴 VULNERABLE" if result.is_vulnerable else (
            "⚠️ ERROR" if result.error else "✅ BLOCKED"
        )
        
        print(f"\n  {result.test_id}: {result.test_name}")
        print(f"    Status: {status}")
        print(f"    Time: {result.response_time:.2f}s")
        
        # Show payload preview
        payload_preview = result.payload[:150].replace('\n', ' ')
        print(f"    Payload: {payload_preview}...")
        
        # Show response preview
        response_preview = result.response[:200].replace('\n', ' ')
        print(f"    Response: {response_preview}...")
        
        # Show detection
        print(f"    Reason: {result.detection_reason}")
    
    def log_error(
        self,
        test_id: str,
        test_name: str,
        payload: str,
        error: str
    ) -> AttackResult:
        """Log an error result."""
        return self.log_result(
            test_id=test_id,
            test_name=test_name,
            payload=payload,
            response="",
            response_time=0.0,
            is_vulnerable=False,
            detection_reason=f"Request failed: {error}",
            error=error
        )
    
    def finish(self) -> Dict[str, Any]:
        """Finish logging and return summary."""
        summary = self.get_summary()
        
        if self._logger:
            self._logger.print_summary()
            self._logger.save_json_log()
            self._logger.save_markdown_log()
        elif self.verbose:
            self._print_summary(summary)
        
        return summary
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        total = len(self.results)
        vulnerable = sum(1 for r in self.results if r.is_vulnerable)
        refused = sum(1 for r in self.results if r.is_refused)
        errors = sum(1 for r in self.results if r.error)
        
        return {
            "category": self.category,
            "total_tests": total,
            "vulnerabilities_found": vulnerable,
            "refused": refused,
            "errors": errors,
            "vulnerability_rate": f"{vulnerable/max(1,total)*100:.1f}%",
            "severity": "HIGH" if vulnerable > total * 0.3 else "MEDIUM" if vulnerable > 0 else "LOW"
        }
    
    def _print_summary(self, summary: Dict[str, Any]):
        """Print summary to console."""
        print(f"\n{'='*70}")
        print(f"  {self.category.upper()} SUMMARY")
        print(f"{'='*70}")
        print(f"  Total: {summary['total_tests']}")
        print(f"  🔴 Vulnerable: {summary['vulnerabilities_found']}")
        print(f"  ✅ Blocked: {summary['total_tests'] - summary['vulnerabilities_found'] - summary['errors']}")
        print(f"  ⚠️ Errors: {summary['errors']}")
        print(f"  Rate: {summary['vulnerability_rate']}")
        print(f"{'='*70}\n")
    
    def get_vulnerable_tests(self) -> List[AttackResult]:
        """Get all vulnerable test results."""
        return [r for r in self.results if r.is_vulnerable]


def create_attack_logger(category: str, verbose: bool = False) -> AttackLogger:
    """Factory function to create an attack logger."""
    return AttackLogger(category, verbose)
