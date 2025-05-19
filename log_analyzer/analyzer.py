import os
import sys
from datetime import datetime  # For timestamped result files
import csv
# Import the log parser class, which is responsible for reading and parsing log files
from .parser import LogParser
# Import detection rule modules for different types of suspicious activity
from .rules import brute_force, privilege_escalation, unauthorized_access

class LogAnalyzer:
    """
    The main engine for analyzing log files for suspicious activity.
    It loads the log file, parses it into structured entries, and applies detection rules.
    """
    def __init__(self, logfile):
        """
        Initialize the LogAnalyzer with a path to a log file.
        Args:
            logfile (str): Path to the log file to analyze.
        """
        self.logfile = logfile  # Store the log file path
        self.parser = LogParser(logfile)  # Create a parser instance for the log file
        self.entries = self.parser.parse()  # Parse the log file into structured entries (list of dicts)

    def analyze(self):
        """
        Run all detection rules on the parsed log entries.
        Returns:
            list: A list of strings describing suspicious activity found in the logs.
        """
        results = []  # List to collect findings from all rules
        # Apply brute-force detection rule
        results.extend(brute_force.detect(self.entries))
        # Apply privilege escalation detection rule
        results.extend(privilege_escalation.detect(self.entries))
        # Apply unauthorized access detection rule
        results.extend(unauthorized_access.detect(self.entries))
        return results  # Return all findings

if __name__ == "__main__":
    # If this script is run directly, parse command-line arguments and run the analyzer
    import argparse
    parser = argparse.ArgumentParser(description="Log Analyzer for Suspicious Activity")
    # Require the user to specify a log file to analyze
    parser.add_argument('--logfile', required=True, help='Path to log file')
    args = parser.parse_args()
    # Create an instance of LogAnalyzer with the provided log file
    analyzer = LogAnalyzer(args.logfile)
    # Run the analysis and get a list of findings
    findings = analyzer.analyze()

    # --- Only save results as CSV ---
    results_dir = os.path.join(os.path.dirname(__file__), '..', 'results')
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_filename = f"results_{timestamp}.csv"
    csv_path = os.path.join(results_dir, csv_filename)
    fieldnames = ['Rule', 'IP', 'Endpoint', 'Method', 'Protocol', 'Status', 'ResponseSize', 'Description', 'Timestamp']
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            if isinstance(finding, dict):
                writer.writerow({
                    'Rule': finding.get('rule',''),
                    'IP': finding.get('ip',''),
                    'Endpoint': finding.get('endpoint',''),
                    'Method': finding.get('method',''),
                    'Protocol': finding.get('protocol',''),
                    'Status': finding.get('status',''),
                    'ResponseSize': finding.get('response_size',''),
                    'Description': finding.get('description',''),
                    'Timestamp': finding.get('timestamp',''),
                })
            else:
                writer.writerow({'Rule':'','IP':'','Endpoint':'','Method':'','Protocol':'','Status':'','ResponseSize':'','Description':str(finding),'Timestamp':''})
    print(f"Results saved as CSV: {os.path.abspath(csv_path)}")
