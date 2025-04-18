# Nessus_Parser
**Nessus Parser** is a lightweight, Python-based GUI tool that allows you to parse `.nessus` files and generate two HTML reports:

- **VA Table:** A concise tabular view of vulnerabilities.
- **Detailed Findings:** A comprehensive view of each vulnerability.

---

The parser was developed in alignment with our organization's reporting format, designed to automate and accelerate the audit reporting workflow and has been successfully tested on:
- Windows 11
- Kali Linux 2024

---

## 🖥️ Features

- Minimal and user-friendly GUI
- Parses `.nessus` files (XML format)
- Generates two structured HTML reports
- Works offline
- Platform-independent (Windows/Linux)

---

## 📦 Requirements

This tool is written in Python and requires the following libraries:

- `tkinter` (standard with Python)
- `xml.etree.ElementTree` (standard)
- `os`, `sys`, `datetime` (standard)

> ✅ No third-party dependencies required

---

## 🚀 How to Use

1. Clone the repository:
   ```bash
   git clone https://github.com/TheMYTH540/Nessus_Parser.git
   cd nessus-parser
   chmod +x nessus-parser.pyw
   python nessus-parser.pyw
