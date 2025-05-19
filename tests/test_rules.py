import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from log_analyzer.rules import brute_force, privilege_escalation, unauthorized_access

def test_brute_force():
    entries = [
        {'ip': '1.2.3.4', 'status': 401},
        {'ip': '1.2.3.4', 'status': 401},
        {'ip': '1.2.3.4', 'status': 401},
    ]
    findings = brute_force.detect(entries)
    assert findings

def test_privilege_escalation():
    entries = [
        {'EventID': 4672, 'AccountName': 'admin', 'PrivilegeList': 'SeDebugPrivilege'}
    ]
    findings = privilege_escalation.detect(entries)
    assert findings

def test_unauthorized_access():
    entries = [
        {'endpoint': '/admin', 'status': 200, 'ip': '1.2.3.4'},
        {'EventID': 4624, 'AccountName': 'admin'}
    ]
    findings = unauthorized_access.detect(entries)
    assert findings
