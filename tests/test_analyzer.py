import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
from log_analyzer.analyzer import LogAnalyzer

def test_analyzer_brute_force():
    analyzer = LogAnalyzer(os.path.join('logs', 'sample_apache.log'))
    findings = analyzer.analyze()
    assert any('Brute-force' in f for f in findings)

def test_analyzer_privilege_escalation():
    analyzer = LogAnalyzer(os.path.join('logs', 'sample_windows_logs.json'))
    findings = analyzer.analyze()
    assert any('Privilege escalation' in f for f in findings)
