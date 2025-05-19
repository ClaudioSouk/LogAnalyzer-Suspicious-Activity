def detect(entries):
    findings = []
    for e in entries:
        # Apache: status 200 on /admin or /restricted
        if e.get('endpoint') in ['/admin', '/restricted', '/secret'] and e.get('status') == 200:
            dt = e.get('datetime', 'unknown time')
            findings.append({
                'rule': 'Unauthorized access',
                'ip': e.get('ip'),
                'endpoint': e.get('endpoint'),
                'method': e.get('method'),
                'protocol': e.get('protocol'),
                'status': e.get('status'),
                'response_size': e.get('response_size'),
                'description': f"Accessed {e.get('endpoint')}",
                'timestamp': dt
            })
        # Windows: EventID 4624 (login success) to restricted account
        if e.get('EventID') == 4624 and e.get('AccountName') == 'admin':
            dt = e.get('datetime', 'unknown time')
            findings.append({
                'rule': 'Unauthorized access',
                'ip': '',
                'endpoint': '',
                'method': '',
                'protocol': '',
                'status': '',
                'response_size': '',
                'description': f"Admin login: {e.get('AccountName')}",
                'timestamp': dt
            })
    return findings
