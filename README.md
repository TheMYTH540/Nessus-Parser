# Nessus Parser
**Nessus Parser** is a lightweight, Python-based GUI tool that allows you to parse `.nessus` files and generate two HTML reports:

- **VA Table:** A concise tabular view of vulnerabilities.
- **Detailed Findings:** A comprehensive view of each vulnerability.


I developed this parser during my work at AKS IT Services Pvt. Ltd. to adhere to the organization’s reporting format. \
Parser was designed to automate and accelerate the audit reporting process for enhanced efficiency — saving valuable time and reducing manual effort.

---

## 🚨 What's New — [Updated Version]

> The Nessus Parser just got a major upgrade. ✨

Here’s what’s new in this updated version:

- ✅ **Improved & modernized GUI** (still minimal, but much sleeker)
- 🔀 **Nessus File Merger** — Easily merge multiple `.nessus` files into one
- 📊 **Rescan Status Sheet Generator** — Compare an Initial Audit and Rescan `.nessus` file to identify which vulnerabilities have been fixed or are still open
- 🌙 **Dark Mode** — Because every good tool needs one 😌
- 💻 **Windows Executable Support** — Now available as `nessus-parser.exe` for instant usage on Windows

---

## 🖥️ Features

- Simple, clean and user-friendly GUI (with optional dark mode)
- Parses `.nessus` files
- Generates two structured HTML Reports:
  - `VA_Table.html`
  - `Detailed_Findings.html`
- Merge multiple `.nessus` files into one
- Create a Rescan Status Sheet for before-after comparison
- Works offline
- Multi-platform support (Windows/Linux)
- Windows `.exe` now available


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
   git clone https://github.com/TheMYTH540/Nessus-Parser.git
   cd Nessus-Parser
   chmod +x Nessus-Parser.pyw
2. Run the parser:
   ```bash
   python Nessus-Parser.pyw 

**Option 2: Run on Windows (EXE)** \
 No Python required! Download the prebuilt nessus-parser.exe from the Releases section. \
 Or, build your own .exe using PyInstaller:
   ```bash
   pyinstaller --onefile --icon=parserlogo.ico --windowed .\Nessus-Parser.pyw
   ```

---
## ✅ Tested On
Parser has been successfully tested on:
- Windows 11
- Kali Linux 2024

---

## 📊 Rescan Status Sheet
Use this feature to compare two .nessus files — typically an initial scan and a rescan — and automatically generate a status sheet showing:
- Vulnerabilities fixed
- Vulnerabilities still present

It’s a fast way to verify remediation progress for audit cycles.

---

## 🖼️ Screenshot

<p align="center">
  <img src="https://github.com/TheMYTH540/Nessus-Parser/blob/main/Screenshot.png?raw=true" alt="Nessus Parser Screenshot"/>
</p>

---
## 🙌 Contribution
Contributions are welcome!
Have an idea or want to make the GUI even cooler? Open an issue or a pull request.

---
## 📄 License
This project is licensed under Apache License 2.0. See the [LICENSE](LICENSE) file for details.

---
## ❤️ Created with Love

This tool was crafted with care and purpose to support faster, more efficient vulnerability reporting.

Made with love ❤️ by **Robin Verma** aka **TheMYTH540**

---
