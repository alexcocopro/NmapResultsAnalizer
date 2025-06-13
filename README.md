# NmapResultAnalizer


This README provides an overview of the NmapResultAnalyzer, its purpose, how to set it up, and how to use it.

## Table of Contents
1.  Introduction
2.  Features
3.  Requirements
4.  Installation
5.  Usage
6.  Nmap Scan Recommendations
7.  Output Report Structure
8.  Customization
9.  Contributing
10. License

---

### 1. Introduction

The Nmap Scan Analyzer is a Python script designed to automate the initial analysis of Nmap scan results. It processes multiple Nmap `.txt` output files from a specified directory (by default, the same directory as the script) and generates a consolidated report. This report highlights potential security risks such as open remote access ports, obsolete software versions, reported vulnerabilities, and suspicious indicators of reverse tunnels or Dark Web connections.

This tool is particularly useful for security analysts, penetration testers, and system administrators who need to quickly identify critical findings across numerous scan targets.

### 2. Features

* **Batch Processing:** Analyzes multiple Nmap scan result files (in `.txt` format) in a single run.
* **Remote Access Detection:** Identifies common ports and services that could allow remote access (e.g., SSH, RDP, Telnet, VNC, SMB, WinRM).
* **Obsolete Version Detection:** Heuristically flags potentially outdated software versions based on predefined patterns, helping to identify systems with known vulnerabilities.
* **Vulnerability Reporting:** Extracts and lists explicit vulnerabilities reported by Nmap's NSE (Nmap Scripting Engine) scripts (e.g., CVEs, exploit mentions).
* **Tunnel & Dark Web Indicators:** Scans for keywords in services, versions, and general scan output that might suggest the presence of reverse tunneling tools or connections to Dark Web services (e.g., ngrok, frp, Tor, .onion domains).
* **Consolidated Report:** Generates a structured `.txt` report summarizing findings per IP address, making it easy to review and prioritize.
* **Kali Linux Friendly:** Designed to run seamlessly on Kali Linux environments.

### 3. Requirements

* **Python 3:** The script is written in Python 3.
* **Nmap Scan Results:** You need Nmap scan output files in plain text (`.txt`) format. It's highly recommended to use Nmap with version detection (`-sV`) and vulnerability scripting (`--script=vuln`) for the most comprehensive results.

    Example Nmap command for generating suitable input files:
    ```bash
    nmap -sS -sV -O --script=vuln -oN my_scan_target.txt <IP_ADDRESS_OR_RANGE>
    ```

### 4. Installation

1.  **Clone the Repository (or download the script):**
    ```bash
    git clone https://github.com/alexcocopro/NmapResultsAnalizer.git
    ```
    (If you just downloaded the script, navigate to its directory.)

2.  **Ensure Python 3 is installed:**
    ```bash
    python3 --version
    ```
    If not installed, follow your Kali Linux distribution's instructions to install it (usually `sudo apt install python3`).

3.  **Place Nmap Scan Files:** Put all your Nmap `.txt` scan result files into the **same directory** where `nmap_analyzer.py` is located.

### 5. Usage

1.  **Open your terminal** in Kali Linux.
2.  **Navigate to the directory** where you saved `nmap_analyzer.py` and your Nmap scan result files.
3.  **Execute the script** using Python 3:
    ```bash
    python3 NmapResultAnalyzer.py
    ```

The script will process the `.txt` files and generate a report named `acceso_remoto_reporte.txt` in the same directory.

### 6. Nmap Scan Recommendations

For optimal results, ensure your Nmap scans include:

* `-sV`: Service/version detection. This is crucial for the script to identify services and their versions.
* `-O`: OS detection. Helps categorize targets.
* `--script=vuln`: Runs common vulnerability detection scripts.
* `-oN <filename.txt>`: Saves the output in normal (plain text) format, which this script parses.

A good general command for generating input for this analyzer:
```bash
nmap -sS -sV -O --script=vuln,default -oN [output_filename].txt [target_ip_or_range]
