from collections import Counter
from datetime import datetime

def detect(entries):
    # Detect brute-force: 3+ failed logins from same IP within sample
    failed = [(e['ip'], e.get('datetime'), e) for e in entries if e.get('status') == 401]
    counter = Counter([ip for ip, _, _ in failed])
    findings = []
    for ip, count in counter.items():
        if count >= 3:
            # Find all timestamps and the first failed entry for this IP
            times = [dt for ip2, dt, _ in failed if ip2 == ip]
            first_entry = next((e for ip2, _, e in failed if ip2 == ip), {})
            if times:
                first = times[0]
                last = times[-1]
                findings.append({
                    'rule': 'Brute-force',
                    'ip': ip,
                    'endpoint': first_entry.get('endpoint', ''),
                    'method': first_entry.get('method', ''),
                    'protocol': first_entry.get('protocol', ''),
                    'status': first_entry.get('status', ''),
                    'response_size': first_entry.get('response_size', ''),
                    'description': f"{count} failed attempts (first: {first}, last: {last})",
                    'timestamp': f"{first} - {last}"
                })
            else:
                findings.append({
                    'rule': 'Brute-force',
                    'ip': ip,
                    'endpoint': first_entry.get('endpoint', ''),
                    'method': first_entry.get('method', ''),
                    'protocol': first_entry.get('protocol', ''),
                    'status': first_entry.get('status', ''),
                    'response_size': first_entry.get('response_size', ''),
                    'description': f"{count} failed attempts",
                    'timestamp': ''
                })
    return findings
