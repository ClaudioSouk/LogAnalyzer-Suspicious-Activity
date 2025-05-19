# Log Analyzer - Suspicious Activity

A simple Python tool that helps you find signs of hacking or suspicious behavior in your computer or server log files. It works by scanning your logs and telling you if it sees things like too many failed logins, people getting special access, or someone looking at things they shouldn’t.

## What does it do?
- **Reads log files** from web servers (Apache) and Windows computers.
- **Looks for common attacks:**
  - Brute-force login attempts (lots of failed logins from the same place)
  - Privilege escalation (someone suddenly gets more permissions)
  - Unauthorized access (someone tries to see restricted pages)
- **Shows you a list of suspicious activity** it finds, so you can take action.
- **Automatically saves the results of every run** in a `results/` folder, with each file named by date and time, so you have a permanent record of all your analysis runs.
- **Each finding now includes the date and time of the suspicious event, just like a real SIEM tool.**

## Who is this for?
- Anyone who wants to check their logs for security problems
- Beginners and entry-level cybersecurity learners
- System administrators and security analysts

## How do I use it?
1. **Install Python** (if you don’t have it already).
2. **Install the requirements:**
   ```powershell
   pip install -r requirements.txt
   ```
3. **Run the analyzer on a log file:**
   ```powershell
   python -m log_analyzer.analyzer --logfile logs/large_sample_apache.log
   ```
   - You can use your own log file instead of the sample.
4. **Read the results in your terminal.**
5. **Check the `results/` folder** for a file with the date and time of your run. This file contains all findings from that analysis, including the timestamp of each suspicious event.

## How do I test if it works?
1. Run the built-in tests:
   ```powershell
   pytest
   ```
2. If all tests pass, the tool is working!

## Example Output
```
Brute-force detected from IP: 127.0.0.1 (failed attempts: 3, first: 19/May/2025:10:00:00, last: 19/May/2025:10:00:02)
Unauthorized access to /admin from 10.0.0.5 at 19/May/2025:10:02:02
```

## Where are my results saved?
- Every time you run the analyzer, a new file is created in the `results/` folder.
- The filename includes the date and time, so you can keep a history of all your analysis runs.
- Each finding in the results file includes the date and time of the suspicious event.


**Architecture Diagram**

```
+-------------------+
|   Log Analyzer    |
+-------------------+
         |
   +-----+-----+
   |           |
Parser     Analyzer
   |           |
 Rules Engine (Brute Force, Privilege Escalation, Unauthorized Access)
         |
     Results Folder (timestamped logs)
```
