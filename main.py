#!/usr/bin/env python3
"""
AI Security Pipeline v2.0 - Main Entry Point
=============================================

Advanced LLM penetration testing with:
- 7 attack categories (20+ tests)
- Parallel execution
- Multi-format reporting
- Circuit breaker & rate limiting

Usage:
    python main.py                     # Run all tests
    python main.py --config config.yaml  # Use YAML config
    python main.py --attacks injection,evasion  # Specific attacks
    python main.py --parallel          # Parallel execution
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import SecurityScanner, ScanConfig, load_scan_config, create_parser


def print_banner():
    """Print startup banner."""
    print("""
+===================================================================+
|                                                                   |
|     _    ___   ____  _____ ____ _   _ ____  ___ _______   __      |
|    / \\  |_ _| / ___|| ____/ ___| | | |  _ \\|_ _|_   _\\ \\ / /      |
|   / _ \\  | |  \\___ \\|  _|| |   | | | | |_) || |  | |  \\ V /       |
|  / ___ \\ | |   ___) | |__| |___| |_| |  _ < | |  | |   | |        |
| /_/   \\_\\___|  |____/|_____\\____|\\___/|_| \\_\\___| |_|   |_|        |
|                                                                   |
|         LLM Penetration Testing Pipeline v2.0                     |
|         Circuit Breaker | Parallel Execution | Multi-Format       |
|                                                                   |
+===================================================================+
    """)


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.quiet:
        print_banner()
    
    # Load config
    if args.config:
        config = load_scan_config(args.config)
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
    
    scanner = SecurityScanner(config)
    
    try:
        if args.health_check:
            is_healthy = scanner.run_health_check()
            sys.exit(0 if is_healthy else 1)
        else:
            scanner.run_all_tests(parallel=args.parallel)
            
            summary = scanner.get_summary()
            
            if not args.quiet:
                print("\n" + "="*60)
                print("📊 FINAL SUMMARY")
                print("="*60)
                print(f"  Categories Tested: {summary['categories_tested']}")
                print(f"  Total Vulnerabilities: {summary['total_vulnerabilities']}")
                
                for key, val in summary.items():
                    if key.endswith("_vulns"):
                        cat = key.replace("_vulns", "").title()
                        print(f"    - {cat}: {val}")
                
                if summary['total_vulnerabilities'] > 0:
                    print("\n  ⚠️  Security issues detected!")
                else:
                    print("\n  ✅ No critical vulnerabilities detected.")
                
                print("="*60 + "\n")
            
            sys.exit(1 if summary['total_vulnerabilities'] > 0 else 0)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
