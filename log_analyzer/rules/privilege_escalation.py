def detect(entries):
    findings = []
    for e in entries:
        # Windows event: 4672 = Special privileges assigned
        if e.get('EventID') == 4672:
            dt = e.get('datetime', 'unknown time')
            findings.append({
                'rule': 'Privilege escalation',
                'ip': '',
                'endpoint': '',
                'method': '',
                'protocol': '',
                'status': '',
                'response_size': '',
                'description': f"{e.get('AccountName')} got {e.get('PrivilegeList')}",
                'timestamp': dt
            })
    return findings
