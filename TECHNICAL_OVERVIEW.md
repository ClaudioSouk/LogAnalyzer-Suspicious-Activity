# Technical Documentation: Log Analyzer - Suspicious Activity

## Overview
This document explains, in clear and structured terms, how the Log Analyzer project works, why it was built this way, and what each part does. It is designed for both technical reviewers and beginners.

---

## Project Structure: What’s in Each Folder?

- **log_analyzer/**
  - All the Python code that does the log analysis.
  - Contains:
    - `analyzer.py`: The main engine that runs everything and now also saves results to a timestamped file in the `results/` folder for every run.
    - `parser.py`: Reads and understands log files.
    - `rules/`: Each file here is a different detection rule (brute-force, privilege escalation, unauthorized access).
- **logs/**
  - Example log files you can use to test the analyzer.
- **results/**
  - Stores the output of every analysis run, with each file named by date and time, so you have a permanent record of all findings.
- **tests/**
  - Automated test scripts that check if your code works correctly.
- **README.md**
  - A beginner-friendly guide on how to use the project.
- **docs/**
  - Extra documentation and diagrams.

---

## How Does the Code Work? (Step by Step)

### 1. Parsing Logs
- The `LogParser` class figures out what kind of log you gave it (Apache or Windows) by looking at the file extension.
- It reads each line (for Apache) or entry (for Windows), and turns it into a Python dictionary with useful fields (like IP, status code, datetime, etc).
- The result: a list of structured entries, ready for analysis.

### 2. Detection Rules
- Each rule is its own Python file in `log_analyzer/rules/`.
- **Brute-force detection:**
  - Looks for 3 or more failed logins (status 401) from the same IP.
  - The output now includes the first and last timestamp of the failed attempts for each IP.
- **Privilege escalation:**
  - Looks for special Windows events (EventID 4672) that mean someone got extra permissions.
  - The output includes the timestamp of the event.
- **Unauthorized access:**
  - Looks for successful access (status 200) to restricted pages (like `/admin` or `/secret`).
  - Also checks for successful admin logins in Windows logs.
  - The output includes the timestamp of the event.

### 3. Main Analyzer Engine
- The `LogAnalyzer` class in `analyzer.py`:
  - Loads and parses the log file.
  - Runs each detection rule on the parsed entries.
  - Collects all findings and returns them as a list of messages.
- When run from the command line, the analyzer:
  - Prints all findings to the terminal.
  - **Saves all findings to a new file in the `results/` folder, with the filename including the date and time of the run.**
  - This gives you a permanent, timestamped record of every analysis.
- You run it from the command line with:
  ```powershell
  python -m log_analyzer.analyzer --logfile <your-log-file>
  ```

### 4. Testing: Why and How?
- The `tests/` folder contains scripts that automatically check if your code works.
- Each test gives your code some sample data and checks if it finds the right suspicious activity.
- Run all tests with:
  ```powershell
  pytest
  ```
- If all tests pass, your code is working as expected!

---

## Why Was It Built This Way? (Design Decisions & Best Practices)

- **Modularity:** Each detection rule is in its own file. Easy to add, remove, or change rules.
- **Readability:** Code is full of comments and uses clear names, so anyone can follow it.
- **Extensibility:** You can add new log formats or rules without changing the whole project.
- **Beginner-Friendly:** Documentation and comments are written for people new to cybersecurity, but the code is professional.
- **Testing:** Automated tests make sure the tool is reliable and easy to update.
- **Result Logging:** Every run is saved in the `results/` folder, so you always have a record of what was found and when. Each finding now includes the date and time of the suspicious event, just like a real SIEM tool.

---
Result explanation:
CSV Explanation:
* The CSV file is a table where each row is a suspicious event, and each column describes a detail about that event. Here’s what each column means:

* Rule: The type of suspicious activity detected (e.g., Brute-force, Unauthorized access).

* IP: The IP address involved in the event.

* Endpoint: The URL or resource accessed (e.g., /login, /admin).

* Method: The HTTP method used (e.g., GET, POST).

* Protocol: The protocol version (e.g., HTTP/1.1).

* Status: The HTTP status code (e.g., 200 for success, 401 for unauthorized).

* ResponseSize: The size of the server’s response in bytes.

* Description: A human-readable summary of what was detected.

* Timestamp: When the suspicious activity happened (or the range, for brute-force).

**--EXAMPLE: Brute-force,127.0.0.1,/login,POST,HTTP/1.1,401,128,"3 failed attempts (first: 19/May/2025:10:00:00, last: 19/May/2025:10:00:02)",19/May/2025:10:00:00 - 19/May/2025:10:00:02

* This means:
- A brute-force attack was detected from IP 127.0.0.1 on the /login endpoint using the POST method.
- The server responded with status 401 (unauthorized) and a response size of 128 bytes.
- There were 3 failed attempts between the two timestamps shown.

## Example Workflow: How Would Someone Use This?

1. User runs the analyzer on a log file:
   ```powershell
   python -m log_analyzer.analyzer --logfile logs/large_sample_apache.log
   ```
2. The tool reads and parses the log, applies all detection rules, and prints any suspicious activity it finds (with timestamps).
3. The tool also saves all findings to a new file in the `results/` folder, named with the date and time.
4. User can run `pytest` to check that all detection logic is working.

---

## Conclusion: What Does This Project Show?
- Real-world knowledge of log analysis and common attack patterns

This project is suitable for both learning and professional evaluation.
