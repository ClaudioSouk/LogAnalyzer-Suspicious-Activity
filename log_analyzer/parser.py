import os
import json
import pandas as pd

class LogParser:
    def __init__(self, logfile):
        self.logfile = logfile

    def parse(self):
        if self.logfile.endswith('.log'):
            return self._parse_apache()
        elif self.logfile.endswith('.json'):
            return self._parse_windows()
        else:
            raise ValueError('Unsupported log format')

    def _parse_apache(self):
        entries = []
        with open(self.logfile, 'r') as f:
            for line in f:
                # Simple Apache log parsing
                parts = line.split()
                if len(parts) < 9:
                    continue
                entry = {
                    'ip': parts[0],
                    'datetime': parts[3].strip('['),
                    'method': parts[5].strip('"'),
                    'endpoint': parts[6],
                    'protocol': parts[7].strip('"') if len(parts) > 7 else '',
                    'status': int(parts[8]),
                    'response_size': int(parts[9]) if len(parts) > 9 else '',
                }
                entries.append(entry)
        return entries

    def _parse_windows(self):
        with open(self.logfile, 'r') as f:
            return json.load(f)
