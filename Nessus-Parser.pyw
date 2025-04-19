import os
import xml.etree.ElementTree as ET
from collections import defaultdict
from tkinter import Tk, Label, Button, filedialog, messagebox
from tkinter import *
from tkinter import ttk
import shutil

'''
   _____                    _             _   _              _____    ____   ____  _____  _   _ 
  / ____|                  | |           | | | |            |  __ \  / __ \ |  _ \|_   _|| \ | |
 | |      _ __  ___   __ _ | |_  ___   __| | | |__   _   _  | |__) || |  | || |_) | | |  |  \| |
 | |     | '__|/ _ \ / _` || __|/ _ \ / _` | | '_ \ | | | | |  _  / | |  | ||  _ <  | |  | . ` |
 | |____ | |  |  __/| (_| || |_|  __/| (_| | | |_) || |_| | | | \ \ | |__| || |_) |_| |_ | |\  |
  \_____||_|   \___| \__,_| \__|\___| \__,_| |_.__/  \__, | |_|  \_\ \____/ |____/|_____||_| \_|
                                                      __/ |                                     
                                                     |___/                                      

'''

# ------------------- Function to Parse Nessus File -------------------
def parse_nessus_file(file_path):
    vulnerabilities = [] # Stores all parsed vulnerabilities

    try:
        tree = ET.parse(file_path) # Parse the XML structure of the Nessus file
        root = tree.getroot() # Get the root element of the XML

        # Loop through all hosts listed in the Nessus scan            
        for report_host in root.findall(".//ReportHost"):
            host_ip = report_host.get("name") # Extract host IP address

            # Loop through all vulnerabilities detected for the current host
            for item in report_host.findall(".//ReportItem"):
                # Extract risk factor (severity) for each vulnerability
                risk_factor_element = item.find(".//risk_factor")
                if risk_factor_element is not None:
                    risk_factor = risk_factor_element.text.strip()
                else:
                    risk_factor = "N/A"

                # Only include vulnerabilities with a defined risk level                        
                if risk_factor in ["Critical", "High", "Medium", "Low"]:
                    vulnerability_name = item.get("pluginName") # Name of the vulnerability
                    cve_elements = item.findall(".//cve") # Associated CVE IDs
                    cve_ids = [cve.text.strip() for cve in cve_elements] if cve_elements else ["N/A"]
                    solution = item.find(".//solution").text.strip() if item.find(".//solution") is not None else "N/A"
                    reference = item.find(".//see_also").text.strip() if item.find(".//see_also") is not None else "N/A"
                    description = item.find(".//description").text.strip() if item.find(".//description") is not None else "N/A"
                    port = item.get('port', '0') # Get the port number, default to '0'

                    # Combine IP and port information
                    ip_port = host_ip if port == '0' else f"{host_ip} (Port No.: {port})"

                    # Add the parsed vulnerability to the list
                    vulnerabilities.append({
                        "IP(Port)": ip_port,
                        "Vulnerability Name": vulnerability_name,
                        "CVE IDs": ', '.join(cve_ids),
                        "Severity": risk_factor,
                        "Recommendation": solution,
                        "Reference": reference,
                        "Description": description
                    })

    except Exception as e:
        # Handle errors during parsing and notify the user
        messagebox.showerror("Error", f"Failed to parse Nessus file: {e}")
        return []

    # Order vulnerabilities by severity
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["Severity"], 5))

    return merge_vulnerabilities(vulnerabilities)


# ------------------- Function to Merge Vulnerabilities -------------------
def merge_vulnerabilities(vulnerabilities):
    merged = defaultdict(lambda: {
        "IPs": set(),
        "Vulnerability Names": set(),
        "CVE IDs": set(),
        "Severity": None,
        "Recommendation": None,
        "Reference": None,
        "Description": None
    })

    for vuln in vulnerabilities:
        name = vuln["Vulnerability Name"]
        merged[name]["IPs"].add(vuln["IP(Port)"]) # Aggregate affected IPs/Ports
        merged[name]["CVE IDs"].update(vuln["CVE IDs"].split(', ')) # Aggregate CVEs
        merged[name]["Severity"] = vuln["Severity"]
        merged[name]["Recommendation"] = vuln["Recommendation"]
        merged[name]["Reference"] = vuln["Reference"]
        merged[name]["Description"] = vuln["Description"]

    # Convert the merged data back into a list format for easy use
    return [
        {
            "IP(Port)": ', '.join(data["IPs"]),
            "Vulnerability Name": name,
            "CVE IDs": ', '.join(data["CVE IDs"]),
            "Severity": data["Severity"],
            "Recommendation": data["Recommendation"],
            "Reference": data["Reference"],
            "Description": data["Description"],
        }
        for name, data in merged.items()
    ]


# ------------------- Function to Generate HTML Report -------------------
def generate_html_report(vulnerabilities, output_file_path):
    severity_color = {
        "Critical": {"order": 1, "color": "#C00000"},
        "High": {"order": 2, "color": "#FF0000"},
        "Medium": {"order": 3, "color": "#ED7D31"},
        "Low": {"order": 4, "color": "#70AD47"}
    }

    html_content = """
    <html>
    <head>
        <title>Nessus Scan Report</title>
        <style>
            body {
                font-family: Verdana, Geneva, sans-serif;
                font-size: 10pt;
                background-color: #f5f5f5;
                margin: 20px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                border: 1px solid #ddd;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }
            th {
                background-color: #1F497D;
                color: white;
            }
            .severity-critical {
                font-weight: bold;
                color: #C00000;
            }
            .severity-high {
                font-weight: bold;
                color: #FF0000;
            }
            .severity-medium {
                font-weight: bold;
                color: #ED7D31;
            }
            .severity-low {
                font-weight: bold;
                color: #70AD47;
            }
            .bold {
                font-weight: bold;
                color: black;
            }
            .center {
                text-align: center;
                vertical-align: middle;
            }
        </style>
    </head>
    <body>
        <h2 style="text-align:center;">Nessus Scan Report</h2>
        <table>
            <tr>
                <th>S.No.</th>
                <th>Affected Asset / IP Address</th>
                <th>Observation / Vulnerability Title</th>
                <th>CVE / CWE</th>
                <th>Severity</th>
                <th>Recommendation</th>
                <th>Reference</th>
                <th>New or Repeated Observation</th>
            </tr>
    """

    for i, vuln in enumerate(vulnerabilities, start=1):
        severity_class = f"severity-{vuln['Severity'].lower()}"
        html_content += f"""
            <tr>
                <td class="center">{i}</td>
                <td>{vuln['IP(Port)']}</td>
                <td><span class="bold">{vuln['Vulnerability Name']}</span></td>
                <td>{vuln['CVE IDs']}</td>
                <td class="center"><span class="{severity_class}">{vuln['Severity']}</span></td>
                <td>{vuln['Recommendation']}</td>
                <td>{vuln['Reference']}</td>
                <td class="center">New</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(output_file_path, 'w') as file:
        file.write(html_content)


# ------------------- Function to Generate Detailed Findings -------------------
def generate_detailed_findings(vulnerabilities, output_file_path):
    html_content = """
    <html>
    <head>
        <title>Detailed Findings Report</title>
        <style>
            body {
                font-family: Verdana, Geneva, sans-serif;
                font-size: 10pt;
                line-height: 1.5;
                text-align: justify;
                background-color: #f5f5f5;
                margin: 20px;
            }
            .bold {
                font-weight: bold;
            }
            .separator {
                text-align: center;
                font-weight: bold;
                padding: 20px 0;
            }
        </style>
    </head>
    <body>
    """

    for index, vuln in enumerate(vulnerabilities, start=1):
        html_content += f"""
        <div>
            <p><span class="bold">Observation {index}:</span></p> <br>
            <p><span class="bold">i. Observation / Vulnerability Title:</span></p><p> {vuln['Vulnerability Name']}</p> <br>
            <p><span class="bold">ii. Affected Asset / IP Address:</span></p><p> {vuln['IP(Port)']}</p> <br>
            <p><span class="bold">iii. Detailed Observation:</span> </p><p>{vuln['Description']}</p> <br>
            <p><span class="bold">iv. CVE/CWE:</span> </p><p> {vuln['CVE IDs']}</p> <br>
            <p><span class="bold">v. Severity:</span> </p><p> {vuln['Severity']}</p> <br>
            <p><span class="bold">vi. Recommendation:</span> </p><p> {vuln['Recommendation']}</p> <br>
            <p><span class="bold">vii. Reference:</span> </p><p> {vuln['Reference']}</p> <br>
         """

        if 'New or Repeat observation' in vuln:
            html_content += f"""
            <p><span class="bold">viii. New or Repeat observation:</span> </p><p> {vuln['New or Repeat observation']}</p> <br>
            """
        else:
            html_content += f"""
            <p><span class="bold">viii. New or Repeat observation:</span> </p><p> New</p> <br>
            """

        html_content += f"""
            <p><span class="bold">ix. Proof of Concept:</span> </p><p> Step I: Go the URL: [Screenshot]</p>
        </div>
        """

        # Add separator between findings
        html_content += """
        <div class="separator">+++++++++++++++++++++++++++++++++++++++++++++++++++++++++</div>
        """

    html_content += """
    </body>
    </html>
    """

    with open(output_file_path, 'w') as file:
        file.write(html_content)


# ------------------- GUI Function to Select Nessus File -------------------
def select_file():
    file_path = filedialog.askopenfilename(
        title="Select Nessus File",
        filetypes=[("Nessus Files", "*.nessus"), ("All Files", "*.*")]
    )
    if file_path:
        process_file(file_path)


# ------------------- GUI Function to Process File -------------------
def process_file(file_path):
    if os.path.exists(file_path):
        vulnerabilities = parse_nessus_file(file_path)
        if not vulnerabilities:
            return

        file_name = os.path.basename(file_path)
        file_base = os.path.splitext(file_name)[0]
        output_dir = os.path.dirname(file_path)

        html_report = os.path.join(output_dir, f"va_table_{file_base}.html")
        detailed_report = os.path.join(output_dir, f"detail_finding_{file_base}.html")

        generate_html_report(vulnerabilities, html_report)
        generate_detailed_findings(vulnerabilities, detailed_report)

        messagebox.showinfo(
            "Success",
            f"Reports generated successfully:\n\n{html_report}\n{detailed_report}"
        )
    else:
        messagebox.showerror("Error", "Invalid file path. Please try again.")


# ------------------- Nessus File Merger -------------------
def merge_nessus_files():
    # Open a file dialog to select multiple Nessus files
    file_paths = filedialog.askopenfilenames(
        title="Select Nessus Files to Merge",
        filetypes=[("Nessus Files", "*.nessus"), ("All Files", "*.*")]
    )
    if not file_paths:
        return

    # Prepare to merge files
    first = True
    main_tree = None
    report = None
    output_dir = "merged_nessus_report"

    try:
        for file_path in file_paths:
            if file_path.endswith(".nessus"):
                print(f":: Parsing {os.path.basename(file_path)}")
                if first:
                    main_tree = ET.parse(file_path)
                    report = main_tree.find('Report')
                    first = False
                else:
                    tree = ET.parse(file_path)
                    for element in tree.findall('.//ReportHost'):
                        report.append(element)

        # Remove old merged output if it exists
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir)

        # Write merged file
        output_file = os.path.join(output_dir, "merged_report.nessus")
        main_tree.write(output_file, encoding="utf-8", xml_declaration=True)
        messagebox.showinfo("Success", f"Nessus files merged successfully!\nMerged file location: {output_file}")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to merge files: {e}")


# ------------------- Severity Levels for Sorting & Coloring -------------------
SEVERITY_LEVELS = {
    "Critical": {"order": 1, "color": "#C00000"},  # Dark Red
    "High": {"order": 2, "color": "#FF0000"},  # Red
    "Medium": {"order": 3, "color": "#ED7D31"},  # Orange
    "Low": {"order": 4, "color": "#70AD47"},  # Green
}


# ------------------- Function to Parse Nessus Files for Rescan Comparison -------------------
def parse_nessus_rescan(file_path):
    """Parse a .nessus file and return vulnerabilities with affected IPs and severity levels."""
    vulnerabilities = defaultdict(lambda: {"IPs": set(), "Severity": "None", "CVE_CWE": "N/A", "Solution": "N/A"})

    tree = ET.parse(file_path)
    root = tree.getroot()

    for report_host in root.findall(".//ReportHost"):
        host_ip = report_host.attrib.get("name")
        for report_item in report_host.findall(".//ReportItem"):
            vuln_name = report_item.attrib.get("pluginName")
            risk_factor = report_item.find("risk_factor")
            severity = risk_factor.text if risk_factor is not None else "None"
            solution = report_item.find("solution")
            if solution is not None and solution.text:
                vulnerabilities[vuln_name]["Solution"] = solution.text.strip()

            # Extract CVE & CWE
            cve = [cve.text for cve in report_item.findall("cve")]
            cwe = report_item.find("cwe")
            cve_cwe = ", ".join(cve) if cve else ""
            if cwe is not None and cwe.text:
                cve_cwe += f", CWE-{cwe.text}" if cve_cwe else f"CWE-{cwe.text}"
            if not cve_cwe:
                cve_cwe = "N/A"
            
            vulnerabilities[vuln_name]["IPs"].add(host_ip)
            vulnerabilities[vuln_name]["Severity"] = severity
            vulnerabilities[vuln_name]["CVE_CWE"] = cve_cwe  # Store CVE/CWE

    return vulnerabilities


# ------------------- Function to Compare Initial & Rescan Files -------------------
def compare_rescan_results(initial_vulns, rescan_vulns):
    """Compare vulnerabilities between initial and rescan results."""
    results = defaultdict(lambda: {"Fixed": set(), "Not Fixed": set(), "Severity": "None", "CVE_CWE": "N/A", "Recommendation": "N/A"})

    for vuln_name, data in initial_vulns.items():
        initial_ips = data["IPs"]
        severity = data["Severity"]
        cve_cwe = data["CVE_CWE"]
        recommendation = data.get("Solution", "N/A")
        rescan_ips = rescan_vulns.get(vuln_name, {}).get("IPs", set())

        fixed_ips = initial_ips - rescan_ips
        not_fixed_ips = initial_ips & rescan_ips

        if (fixed_ips or not_fixed_ips) and severity in SEVERITY_LEVELS:
            results[vuln_name]["Fixed"] = fixed_ips
            results[vuln_name]["Not Fixed"] = not_fixed_ips
            results[vuln_name]["Severity"] = severity
            results[vuln_name]["CVE_CWE"] = cve_cwe  # Preserve CVE/CWE info
            results[vuln_name]["Recommendation"] = recommendation

    return results


# ------------------- Function to Generate Rescan Status Report -------------------
def generate_rescan_status_report(results, output_file):
    """Generate an HTML report for rescan status."""
    sorted_results = sorted(results.items(), key=lambda x: SEVERITY_LEVELS[x[1]["Severity"]]["order"])

    html_content = """
    <html>
    <head>
        <title>Rescan Status Report</title>
        <style>
            body {
                font-family: Verdana, sans-serif;
                font-size: 10px;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                border: 2px solid black;
            }
            th, td {
                border: 2px solid black;
                text-align: left;
                padding: 8px;
            }
            th {
                background-color: #1F497D;
                color: white;
            }
            .severity {
                font-weight: bold;
            }
            .fixed {
                color: green;
                font-weight: bold;
            }
            .not-fixed {
                color: red;
                font-weight: bold;
            }
            .bold {
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Rescan Status Report</h1>
        <table>
            <tr>
                <th>S. No.</th>
                <th>Affected Asset / IP Address</th>
                <th>Vulnerability Title</th>
                <th>CVE / CWE</th>
                <th>Severity</th>
                <th>Recommendation</th>
                <th>Current Status</th>
                <th>New or Repeated Observation</th>
            </tr>
    """

    for idx, (vuln_name, data) in enumerate(sorted_results, start=1):
        severity = data["Severity"]
        severity_color = SEVERITY_LEVELS[severity]["color"]
        cve_cwe = data["CVE_CWE"]
        recommendation = data.get("Recommendation")

        affected_ips = "<br>".join(sorted(data["Fixed"] | data["Not Fixed"]))
        fixed_ips = "<br>".join(sorted(data["Fixed"]))
        not_fixed_ips = "<br>".join(sorted(data["Not Fixed"]))

        status = f"""
            <span class="not-fixed">NOT FIXED:</span><br>
            {not_fixed_ips}<br><br>
            <span class="fixed">FIXED:</span><br>
            {fixed_ips}
        """

        html_content += f"""
            <tr>
                <td>{idx}</td>
                <td>{affected_ips}</td>
                <td><span class="bold">{vuln_name}</span></td>
                <td>{cve_cwe}</td>
                <td class="severity" style="color: {severity_color};">{severity}</td>
                <td>{recommendation}</td>
                <td>{status}</td>
                <td>New</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(output_file, "w") as file:
        file.write(html_content)
    messagebox.showinfo("Success", f"Rescan Status Report generated successfully:\n{output_file}")


# ------------------- Function to Process Rescan Files -------------------
def process_rescan_files():
    """Allow user to select initial and rescan Nessus files and generate Rescan Status Report."""
    Tk().withdraw()

    messagebox.showinfo("Select Initial Audit File", "Please select the Initial Nessus Scan file.")
    initial_file = filedialog.askopenfilename(filetypes=[("Nessus Files", "*.nessus")])
    if not initial_file:
        messagebox.showerror("Error", "No initial scan file selected.")
        return

    messagebox.showinfo("Select Rescan File", "Please select the Rescan Nessus file.")
    rescan_file = filedialog.askopenfilename(filetypes=[("Nessus Files", "*.nessus")])
    if not rescan_file:
        messagebox.showerror("Error", "No rescan file selected.")
        return

    initial_vulns = parse_nessus_rescan(initial_file)
    rescan_vulns = parse_nessus_rescan(rescan_file)

    results = compare_rescan_results(initial_vulns, rescan_vulns)

    generate_rescan_status_report(results, "Rescan_Status_Report.html")

# ------------------- GUI Launcher -------------------

def launch_gui():
    def apply_theme(dark):
        bg = "#1e1e2f" if dark else "#f5f7fa"
        fg_main = "#ecf0f1" if dark else "#2c3e50"
        fg_sub = "#bdc3c7" if dark else "#7f8c8d"

        root.configure(bg=bg)
        header_label.config(bg=bg, fg=fg_main)
        creator_label.config(bg=bg, fg=fg_sub)

        # Update button colors
        buttons[0].config(bg="#2980b9" if dark else "#3498db", activebackground="#2471a3" if dark else "#2980b9")
        buttons[1].config(bg="#16a085" if dark else "#1abc9c", activebackground="#138d75" if dark else "#16a085")
        buttons[2].config(bg="#d68910" if dark else "#f39c12", activebackground="#b9770e" if dark else "#d68910")
        buttons[3].config(bg="#c0392b" if dark else "#e74c3c", activebackground="#922b21" if dark else "#c0392b")

    def toggle_dark_mode():
        apply_theme(dark_mode_var.get())

    root = Tk()
    root.title("Nessus Parser by Robin")
    root.geometry("500x550")
    root.configure(bg="#f5f7fa")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=10, background="#3498db", foreground="white")
    style.map("TButton", background=[("active", "#2980b9")])

    # Header Label
    header_label = Label(root, text="Nessus Parser", font=("Segoe UI", 20, "bold"), bg="#f5f7fa", fg="#2c3e50")
    header_label.pack(pady=(40, 10))

    # Subtitle
    creator_label = Label(root, text="Created with Love by Robin Verma", font=("Segoe UI", 11, "bold"), bg="#f5f7fa", fg="#7f8c8d")
    creator_label.pack(pady=(0, 30))

    # Button Creator
    buttons = []
    def create_colored_button(text, command, bg_color, hover_color):
        btn = Button(root, text=text, command=command, width=25, height=2,
                     font=("Segoe UI", 11, "bold"), bg=bg_color, fg="white",
                     bd=3, relief="flat", activebackground=hover_color)
        btn.pack(pady=10)
        buttons.append(btn)
        return btn

    create_colored_button("Nessus Parser", select_file, "#3498db", "#2980b9")
    create_colored_button("Nessus File Merger", merge_nessus_files, "#1abc9c", "#16a085")
    create_colored_button("Rescan Status Sheet", process_rescan_files, "#f39c12", "#d68910")
    create_colored_button("Exit", root.quit, "#e74c3c", "#c0392b")

    # Dark mode switch
    dark_mode_var = BooleanVar()
    style.configure("Switch.TCheckbutton", background="#f5f7fa", font=("Segoe UI", 10, "bold"))
    dark_mode_switch = ttk.Checkbutton(root, text="Dark Mode", style="Switch.TCheckbutton",
                                       variable=dark_mode_var, command=toggle_dark_mode)
    dark_mode_switch.place(relx=1.0, rely=1.0, x=-30, y=-20, anchor="se")

    apply_theme(False)
    root.mainloop()

# ------------------- Main Entry Point -------------------
if __name__ == "__main__":
    launch_gui()