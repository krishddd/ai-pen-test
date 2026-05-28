"""
AI Security Pipeline v2.0 - Enhanced Scanner Orchestrator
==========================================================

Advanced orchestrator with:
- Parallel test execution
- Progress bars (tqdm)
- YAML configuration
- Adaptive severity
- Session management
"""

import os
import sys
import argparse
import yaml
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

try:
    from tqdm import tqdm
except ImportError:
    # Fallback if tqdm not installed
    def tqdm(iterable, **kwargs):
        return iterable

from client import LLMClient, ClientConfig, load_config_from_yaml
from attacks import injection, dos, leakage, poisoning, evasion, extraction, multi_stage
from reports.generator import ReportGenerator


@dataclass
class ScanConfig:
    """Configuration for security scan."""
    base_url: str = "http://213.163.75.246:50049"
    model: str = "qwen2.5:7b"
    api_key: str = ""
    timeout: int = 30
    
    # Test selection
    attack_categories: List[str] = field(default_factory=lambda: [
        "injection", "dos", "leakage", "poisoning", "evasion", "extraction", "multi_stage"
    ])
    
    # Execution settings
    concurrency: int = 5
    
    # DoS settings
    concurrent_requests: int = 30
    payload_size: int = 10000
    
    # Output
    report_path: str = "security_report"
    report_formats: List[str] = field(default_factory=lambda: ["markdown", "json"])
    verbose: bool = True
    progress_bar: bool = True


def load_scan_config(config_path: str) -> ScanConfig:
    """Load scan configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
        
        target = data.get("target", {})
        scanner = data.get("scanner", {})
        attacks = data.get("attacks", {})
        reporting = data.get("reporting", {})
        auth = data.get("authentication", {})
        
        # Determine enabled attacks
        enabled_attacks = []
        for attack_name, attack_config in attacks.items():
            if isinstance(attack_config, dict) and attack_config.get("enabled", True):
                enabled_attacks.append(attack_name)
        
        if not enabled_attacks:
            enabled_attacks = scanner.get("attack_categories", ["injection", "dos", "leakage"])
        
        return ScanConfig(
            base_url=target.get("base_url", "http://213.163.75.246:50049"),
            model=target.get("model", "qwen2.5:7b"),
            api_key=auth.get("api_key", ""),
            timeout=data.get("client", {}).get("timeout", 30),
            attack_categories=enabled_attacks,
            concurrency=scanner.get("concurrency", 5),
            concurrent_requests=attacks.get("dos", {}).get("concurrent_requests", [30])[0] if isinstance(attacks.get("dos", {}).get("concurrent_requests"), list) else 30,
            payload_size=attacks.get("dos", {}).get("token_counts", [10000])[-1] if isinstance(attacks.get("dos", {}).get("token_counts"), list) else 10000,
            report_path=reporting.get("output_dir", "./reports") + "/security_report",
            report_formats=reporting.get("formats", ["markdown", "json"]),
            verbose=scanner.get("verbose", True),
            progress_bar=scanner.get("progress_bar", True),
        )
    except Exception as e:
        print(f"Warning: Could not load config from {config_path}: {e}")
        return ScanConfig()


class SecurityScanner:
    """Enhanced orchestrator for security tests with parallel execution."""
    
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        
        # Initialize client
        client_config = ClientConfig(
            base_url=self.config.base_url,
            model=self.config.model,
            api_key=self.config.api_key,
            timeout=self.config.timeout
        )
        self.client = LLMClient(client_config)
        
        # Initialize report generator
        self.reporter = ReportGenerator(
            self.config.base_url,
            self.config.model
        )
        
        # Results storage
        self.results = {
            "health_check": None,
            "injection": [],
            "dos": [],
            "leakage": [],
            "poisoning": [],
            "evasion": [],
            "extraction": [],
            "multi_stage": [],
        }
        
        self.lock = threading.Lock()
    
    def _print(self, message: str):
        """Print if verbose mode enabled."""
        if self.config.verbose:
            print(message)
    
    def _progress(self, iterable, desc: str, total: int = None):
        """Wrap iterable with progress bar if enabled."""
        if self.config.progress_bar:
            return tqdm(iterable, desc=desc, total=total, leave=False)
        return iterable
    
    def run_health_check(self) -> bool:
        """Run reconnaissance and health check."""
        self._print("\n" + "="*60)
        self._print("🔍 RECONNAISSANCE & HEALTH CHECK")
        self._print("="*60)
        
        is_healthy, message = self.client.health_check()
        self.results["health_check"] = {"healthy": is_healthy, "message": message}
        
        if is_healthy:
            self._print(f"  ✅ {message}")
        else:
            self._print(f"  ❌ {message}")
        
        # Check embedding model
        embed_available, embed_message = self.client.check_embedding_model()
        self._print(f"  📊 Embedding model: {embed_message}")
        
        # Get client metrics
        metrics = self.client.get_metrics()
        self._print(f"  📈 Circuit breaker: {metrics['circuit_breaker_state']}")
        
        return is_healthy
    
    def run_injection_tests(self) -> List[Any]:
        """Run prompt injection tests."""
        self._print("\n" + "="*60)
        self._print("💉 PROMPT INJECTION TESTS")
        self._print("="*60)
        
        results = injection.run_injection_tests(self.client, self.config.verbose)
        
        with self.lock:
            self.results["injection"] = results
        
        summary = injection.get_test_summary(results)
        self._print(f"\n  Summary: {summary['vulnerabilities_found']}/{summary['total_tests']} vulnerabilities")
        
        return results
    
    def run_dos_tests(self) -> List[Any]:
        """Run denial of service tests."""
        self._print("\n" + "="*60)
        self._print("⚡ DENIAL OF SERVICE TESTS")
        self._print("="*60)
        
        results = dos.run_dos_tests(
            self.client,
            self.config.concurrent_requests,
            self.config.payload_size,
            self.config.verbose
        )
        
        with self.lock:
            self.results["dos"] = results
        
        summary = dos.get_test_summary(results)
        self._print(f"\n  Summary: {summary['vulnerabilities_found']}/{summary['total_tests']} vulnerabilities")
        
        return results
    
    def run_leakage_tests(self) -> List[Any]:
        """Run data leakage tests."""
        self._print("\n" + "="*60)
        self._print("🔐 DATA LEAKAGE TESTS")
        self._print("="*60)
        
        results = leakage.run_leakage_tests(self.client, self.config.verbose)
        
        with self.lock:
            self.results["leakage"] = results
        
        summary = leakage.get_test_summary(results)
        self._print(f"\n  Summary: {summary['vulnerabilities_found']}/{summary['total_tests']} vulnerabilities")
        
        return results
    
    def run_poisoning_tests(self) -> List[Any]:
        """Run model poisoning tests."""
        self._print("\n" + "="*60)
        self._print("☠️ MODEL POISONING TESTS")
        self._print("="*60)
        
        results = poisoning.run_poisoning_tests(self.client, self.config.verbose)
        
        with self.lock:
            self.results["poisoning"] = results
        
        summary = poisoning.get_test_summary(results)
        self._print(f"\n  Summary: {summary['vulnerabilities_found']}/{summary['total_tests']} vulnerabilities")
        
        return results
    
    def run_evasion_tests(self) -> List[Any]:
        """Run defense evasion tests."""
        self._print("\n" + "="*60)
        self._print("🥷 DEFENSE EVASION TESTS")
        self._print("="*60)
        
        results = evasion.run_evasion_tests(self.client, self.config.verbose)
        
        with self.lock:
            self.results["evasion"] = results
        
        summary = evasion.get_test_summary(results)
        self._print(f"\n  Summary: {summary['filters_bypassed']}/{summary['total_tests']} filters bypassed")
        
        return results
    
    def run_extraction_tests(self) -> List[Any]:
        """Run model extraction tests."""
        self._print("\n" + "="*60)
        self._print("🔬 MODEL EXTRACTION TESTS")
        self._print("="*60)
        
        results = extraction.run_extraction_tests(self.client, self.config.verbose)
        
        with self.lock:
            self.results["extraction"] = results
        
        summary = extraction.get_test_summary(results)
        self._print(f"\n  Summary: {summary['information_disclosed']}/{summary['total_tests']} disclosures")
        
        return results
    
    def run_multi_stage_tests(self) -> List[Any]:
        """Run multi-stage attack chains."""
        self._print("\n" + "="*60)
        self._print("🔗 MULTI-STAGE ATTACK CHAINS")
        self._print("="*60)
        
        results = multi_stage.run_multi_stage_tests(self.client, self.config.verbose)
        
        with self.lock:
            self.results["multi_stage"] = results
        
        summary = multi_stage.get_test_summary(results)
        self._print(f"\n  Summary: {summary['chains_with_success']}/{summary['total_chains']} chains successful")
        
        return results
    
    def run_tests_parallel(self, categories: List[str]) -> Dict[str, Any]:
        """Run multiple test categories in parallel."""
        self._print("\n🚀 Running tests in parallel...")
        
        # Map category names to test functions
        test_functions = {
            "injection": self.run_injection_tests,
            "dos": self.run_dos_tests,
            "leakage": self.run_leakage_tests,
            "poisoning": self.run_poisoning_tests,
            "evasion": self.run_evasion_tests,
            "extraction": self.run_extraction_tests,
            "multi_stage": self.run_multi_stage_tests,
        }
        
        # Filter to only requested categories
        tasks = [(cat, test_functions[cat]) for cat in categories if cat in test_functions]
        
        with ThreadPoolExecutor(max_workers=min(len(tasks), self.config.concurrency)) as executor:
            futures = {executor.submit(func): cat for cat, func in tasks}
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Categories", disable=not self.config.progress_bar):
                category = futures[future]
                try:
                    future.result()
                except Exception as e:
                    self._print(f"  ❌ Error in {category}: {str(e)}")
        
        return self.results
    
    def run_all_tests(self, parallel: bool = False):
        """Run all enabled security tests."""
        self._print("\n" + "="*60)
        self._print("🛡️  AI SECURITY PIPELINE v2.0")
        self._print("="*60)
        self._print(f"  Target: {self.config.base_url}")
        self._print(f"  Model: {self.config.model}")
        self._print(f"  Categories: {', '.join(self.config.attack_categories)}")
        self._print("="*60)
        
        # Always run health check first
        if not self.run_health_check():
            self._print("\n⚠️  Target is not healthy. Some tests may fail.")
        
        # Run tests
        if parallel and len(self.config.attack_categories) > 1:
            self.run_tests_parallel(self.config.attack_categories)
        else:
            for category in self.config.attack_categories:
                if category == "injection":
                    self.run_injection_tests()
                elif category == "dos":
                    self.run_dos_tests()
                elif category == "leakage":
                    self.run_leakage_tests()
                elif category == "poisoning":
                    self.run_poisoning_tests()
                elif category == "evasion":
                    self.run_evasion_tests()
                elif category == "extraction":
                    self.run_extraction_tests()
                elif category == "multi_stage":
                    self.run_multi_stage_tests()
        
        # Generate reports
        self._print("\n" + "="*60)
        self._print("📄 GENERATING REPORTS")
        self._print("="*60)
        
        # Add results to reporter
        self.reporter.add_health_check_result(
            self.results["health_check"]["healthy"],
            self.results["health_check"]["message"]
        )
        
        if self.results["injection"]:
            self.reporter.add_injection_results(self.results["injection"])
        if self.results["dos"]:
            self.reporter.add_dos_results(self.results["dos"])
        if self.results["leakage"]:
            self.reporter.add_leakage_results(self.results["leakage"])
        if self.results["poisoning"]:
            self.reporter.add_poisoning_results(self.results["poisoning"])
        if self.results["evasion"]:
            self.reporter.add_evasion_results(self.results["evasion"])
        if self.results["extraction"]:
            self.reporter.add_extraction_results(self.results["extraction"])
        if self.results["multi_stage"]:
            self.reporter.add_multi_stage_results(self.results["multi_stage"])
        
        # Generate in all requested formats
        for fmt in self.config.report_formats:
            output_path = f"{self.config.report_path}.{fmt if fmt != 'markdown' else 'md'}"
            self.reporter.generate_report(output_path, fmt)
            self._print(f"  📝 {fmt.upper()}: {output_path}")
        
        # Print client metrics
        self._print("\n" + "="*60)
        self._print("📊 CLIENT METRICS")
        self._print("="*60)
        metrics = self.client.get_metrics()
        self._print(f"  Total Requests: {metrics['total_requests']}")
        self._print(f"  Success Rate: {metrics['success_rate']}")
        self._print(f"  Avg Latency: {metrics['avg_latency']}")
        self._print(f"  P95 Latency: {metrics['p95_latency']}")
        
        return self.results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get overall summary of all tests."""
        summary = {
            "target": self.config.base_url,
            "model": self.config.model,
            "health_check": self.results["health_check"],
            "categories_tested": len(self.config.attack_categories),
            "total_vulnerabilities": 0,
        }
        
        # Count vulnerabilities per category
        if self.results["injection"]:
            summary["injection_vulns"] = sum(1 for r in self.results["injection"] if r.success)
            summary["total_vulnerabilities"] += summary["injection_vulns"]
        
        if self.results["dos"]:
            summary["dos_vulns"] = sum(1 for r in self.results["dos"] if r.success)
            summary["total_vulnerabilities"] += summary["dos_vulns"]
        
        if self.results["leakage"]:
            summary["leakage_vulns"] = sum(1 for r in self.results["leakage"] if r.success)
            summary["total_vulnerabilities"] += summary["leakage_vulns"]
        
        if self.results["poisoning"]:
            summary["poisoning_vulns"] = sum(1 for r in self.results["poisoning"] if r.success)
            summary["total_vulnerabilities"] += summary["poisoning_vulns"]
        
        if self.results["evasion"]:
            summary["evasion_vulns"] = sum(1 for r in self.results["evasion"] if r.success)
            summary["total_vulnerabilities"] += summary["evasion_vulns"]
        
        if self.results["extraction"]:
            summary["extraction_vulns"] = sum(1 for r in self.results["extraction"] if r.success)
            summary["total_vulnerabilities"] += summary["extraction_vulns"]
        
        if self.results["multi_stage"]:
            summary["multi_stage_vulns"] = sum(1 for r in self.results["multi_stage"] if r.success)
            summary["total_vulnerabilities"] += summary["multi_stage_vulns"]
        
        return summary


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="AI Security Pipeline v2.0 - LLM Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --all                     Run all tests
  python scanner.py --config config.yaml      Use YAML configuration
  python scanner.py --attacks injection,dos   Run specific attacks
  python scanner.py --parallel                Run tests in parallel
        """
    )
    
    parser.add_argument("--config", "-c", help="Path to YAML configuration file")
    parser.add_argument("--url", "-u", default="http://213.163.75.246:50049")
    parser.add_argument("--model", "-m", default="qwen2.5:7b")
    parser.add_argument("--api-key", "-k", default="")
    parser.add_argument("--timeout", "-t", type=int, default=30)
    parser.add_argument("--all", "-a", action="store_true", help="Run all tests")
    parser.add_argument("--health-check", action="store_true")
    parser.add_argument("--attacks", help="Comma-separated attack categories")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--parallel", "-p", action="store_true", help="Run tests in parallel")
    parser.add_argument("--output", "-o", default="security_report")
    parser.add_argument("--format", "-f", default="markdown,json")
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--no-progress", action="store_true")
    
    return parser


def main():
    """Main entry point for CLI usage."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Load config from file or arguments
    if args.config:
        config = load_scan_config(args.config)
        # Override with CLI args
        if args.api_key:
            config.api_key = args.api_key
    else:
        categories = args.attacks.split(",") if args.attacks else ["injection", "dos", "leakage"]
        if args.all:
            categories = ["injection", "dos", "leakage", "poisoning", "evasion", "extraction", "multi_stage"]
        
        config = ScanConfig(
            base_url=args.url,
            model=args.model,
            api_key=args.api_key,
            timeout=args.timeout,
            attack_categories=categories,
            concurrency=args.concurrency,
            report_path=args.output,
            report_formats=args.format.split(","),
            verbose=not args.quiet,
            progress_bar=not args.no_progress,
        )
    
    # Run scanner
    scanner = SecurityScanner(config)
    
    if args.health_check:
        scanner.run_health_check()
    else:
        scanner.run_all_tests(parallel=args.parallel)
        
        if not args.quiet:
            summary = scanner.get_summary()
            print("\n" + "="*60)
            print("📊 FINAL SUMMARY")
            print("="*60)
            print(f"  Total Vulnerabilities: {summary['total_vulnerabilities']}")
            print("="*60)


if __name__ == "__main__":
    main()
