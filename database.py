"""
AI Security Pipeline v2.1 - SQLite Database Storage
=====================================================

Persistent storage for:
- Scan history
- Test results
- Trend analysis
- Comparison reports
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class ScanRecord:
    """Record of a security scan."""
    scan_id: str
    timestamp: str
    target_url: str
    model_name: str
    total_tests: int
    total_vulnerabilities: int
    risk_score: float
    attack_categories: str  # JSON list
    results_json: str  # Full results as JSON
    report_path: str = ""
    duration_seconds: float = 0.0


@dataclass
class TestResult:
    """Individual test result."""
    scan_id: str
    test_id: str
    test_name: str
    category: str
    success: bool
    severity: str
    response_time: float
    details: str  # JSON


class SecurityDatabase:
    """SQLite database for security scan storage."""
    
    def __init__(self, db_path: str = "security_scans.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    total_tests INTEGER DEFAULT 0,
                    total_vulnerabilities INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0,
                    attack_categories TEXT,
                    results_json TEXT,
                    report_path TEXT,
                    duration_seconds REAL DEFAULT 0.0
                )
            """)
            
            # Individual test results
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    test_id TEXT NOT NULL,
                    test_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    success INTEGER DEFAULT 0,
                    severity TEXT,
                    response_time REAL DEFAULT 0.0,
                    details TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)
            
            # Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_scan ON test_results(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_category ON test_results(category)")
            
            conn.commit()
    
    def save_scan(self, record: ScanRecord) -> bool:
        """Save a scan record to the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO scans 
                    (scan_id, timestamp, target_url, model_name, total_tests, 
                     total_vulnerabilities, risk_score, attack_categories, 
                     results_json, report_path, duration_seconds)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.scan_id,
                    record.timestamp,
                    record.target_url,
                    record.model_name,
                    record.total_tests,
                    record.total_vulnerabilities,
                    record.risk_score,
                    record.attack_categories,
                    record.results_json,
                    record.report_path,
                    record.duration_seconds
                ))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error saving scan: {e}")
            return False
    
    def save_test_result(self, result: TestResult) -> bool:
        """Save an individual test result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO test_results 
                    (scan_id, test_id, test_name, category, success, 
                     severity, response_time, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.scan_id,
                    result.test_id,
                    result.test_name,
                    result.category,
                    1 if result.success else 0,
                    result.severity,
                    result.response_time,
                    result.details
                ))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error saving test result: {e}")
            return False
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific scan by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recent scans."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_scans_by_target(self, target_url: str) -> List[Dict[str, Any]]:
        """Get all scans for a specific target."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans 
                WHERE target_url = ?
                ORDER BY timestamp DESC
            """, (target_url,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_test_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all test results for a scan."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM test_results 
                WHERE scan_id = ?
                ORDER BY category, test_id
            """, (scan_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_vulnerability_trends(self, target_url: str, days: int = 30) -> Dict[str, Any]:
        """Get vulnerability trends for a target over time."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    DATE(timestamp) as date,
                    AVG(total_vulnerabilities) as avg_vulns,
                    AVG(risk_score) as avg_risk,
                    COUNT(*) as scan_count
                FROM scans 
                WHERE target_url = ?
                  AND timestamp >= datetime('now', ?)
                GROUP BY DATE(timestamp)
                ORDER BY date
            """, (target_url, f'-{days} days'))
            
            rows = cursor.fetchall()
            return {
                "dates": [r[0] for r in rows],
                "avg_vulnerabilities": [r[1] for r in rows],
                "avg_risk_score": [r[2] for r in rows],
                "scan_counts": [r[3] for r in rows]
            }
    
    def get_category_breakdown(self, scan_id: str) -> Dict[str, Dict[str, int]]:
        """Get vulnerability breakdown by category for a scan."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    category,
                    COUNT(*) as total,
                    SUM(success) as vulnerable
                FROM test_results 
                WHERE scan_id = ?
                GROUP BY category
            """, (scan_id,))
            
            return {
                row[0]: {"total": row[1], "vulnerable": row[2]}
                for row in cursor.fetchall()
            }
    
    def compare_scans(self, scan_id_1: str, scan_id_2: str) -> Dict[str, Any]:
        """Compare two scans and show differences."""
        scan1 = self.get_scan(scan_id_1)
        scan2 = self.get_scan(scan_id_2)
        
        if not scan1 or not scan2:
            return {"error": "One or both scans not found"}
        
        results1 = {r["test_id"]: r for r in self.get_test_results(scan_id_1)}
        results2 = {r["test_id"]: r for r in self.get_test_results(scan_id_2)}
        
        # Find differences
        new_vulns = []
        fixed_vulns = []
        unchanged_vulns = []
        
        all_tests = set(results1.keys()) | set(results2.keys())
        
        for test_id in all_tests:
            r1 = results1.get(test_id)
            r2 = results2.get(test_id)
            
            if r1 and r2:
                if r1["success"] and not r2["success"]:
                    fixed_vulns.append(test_id)
                elif not r1["success"] and r2["success"]:
                    new_vulns.append(test_id)
                elif r1["success"] and r2["success"]:
                    unchanged_vulns.append(test_id)
            elif r2 and r2["success"]:
                new_vulns.append(test_id)
        
        return {
            "scan1": {
                "id": scan_id_1,
                "timestamp": scan1["timestamp"],
                "vulnerabilities": scan1["total_vulnerabilities"]
            },
            "scan2": {
                "id": scan_id_2,
                "timestamp": scan2["timestamp"],
                "vulnerabilities": scan2["total_vulnerabilities"]
            },
            "diff": {
                "new_vulnerabilities": new_vulns,
                "fixed_vulnerabilities": fixed_vulns,
                "unchanged_vulnerabilities": unchanged_vulns,
                "delta": scan2["total_vulnerabilities"] - scan1["total_vulnerabilities"]
            }
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]
            
            # Total tests run
            cursor.execute("SELECT COUNT(*) FROM test_results")
            total_tests = cursor.fetchone()[0]
            
            # Total vulnerabilities found
            cursor.execute("SELECT SUM(total_vulnerabilities) FROM scans")
            total_vulns = cursor.fetchone()[0] or 0
            
            # Average risk score
            cursor.execute("SELECT AVG(risk_score) FROM scans")
            avg_risk = cursor.fetchone()[0] or 0.0
            
            # Unique targets
            cursor.execute("SELECT COUNT(DISTINCT target_url) FROM scans")
            unique_targets = cursor.fetchone()[0]
            
            # Most vulnerable category
            cursor.execute("""
                SELECT category, SUM(success) as vulns 
                FROM test_results 
                GROUP BY category 
                ORDER BY vulns DESC 
                LIMIT 1
            """)
            row = cursor.fetchone()
            most_vuln_cat = row[0] if row else "N/A"
            
            return {
                "total_scans": total_scans,
                "total_tests_run": total_tests,
                "total_vulnerabilities": total_vulns,
                "average_risk_score": round(avg_risk, 2),
                "unique_targets": unique_targets,
                "most_vulnerable_category": most_vuln_cat
            }


# ============================================================================
# Convenience Functions
# ============================================================================

_db = None

def get_database(db_path: str = "security_scans.db") -> SecurityDatabase:
    """Get or create the global database instance."""
    global _db
    if _db is None:
        _db = SecurityDatabase(db_path)
    return _db


def save_scan_to_db(
    scan_id: str,
    target_url: str,
    model_name: str,
    results: Dict[str, Any],
    duration: float = 0.0
) -> bool:
    """Convenience function to save a scan."""
    db = get_database()
    
    total_tests = sum(r.get("total_tests", 0) for r in results.values())
    total_vulns = sum(r.get("vulnerabilities_found", 0) for r in results.values())
    risk_score = min(10.0, total_vulns * 0.5)
    
    record = ScanRecord(
        scan_id=scan_id,
        timestamp=datetime.now().isoformat(),
        target_url=target_url,
        model_name=model_name,
        total_tests=total_tests,
        total_vulnerabilities=total_vulns,
        risk_score=risk_score,
        attack_categories=json.dumps(list(results.keys())),
        results_json=json.dumps(results),
        duration_seconds=duration
    )
    
    return db.save_scan(record)


if __name__ == "__main__":
    # Test the database
    db = SecurityDatabase("test_security.db")
    
    # Create a test scan
    record = ScanRecord(
        scan_id="test-001",
        timestamp=datetime.now().isoformat(),
        target_url="http://localhost:11434",
        model_name="llama2",
        total_tests=43,
        total_vulnerabilities=10,
        risk_score=5.0,
        attack_categories='["injection", "dos", "leakage"]',
        results_json='{}',
        duration_seconds=120.5
    )
    
    db.save_scan(record)
    
    # Retrieve and print
    stats = db.get_statistics()
    print(f"Database statistics: {stats}")
    
    scans = db.get_recent_scans(5)
    print(f"Recent scans: {len(scans)}")
