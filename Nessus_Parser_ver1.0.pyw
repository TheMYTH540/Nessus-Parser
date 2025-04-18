import os
import xml.etree.ElementTree as ET
from collections import defaultdict
from tkinter import Tk, Label, Button, filedialog, messagebox
from tkinter import ttk


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
            <p><span class="bold">i. Observation / Vulnerability Title:</span></p><p> {vuln['Vulnerability Name']}</p>
            <p><span class="bold">ii. Affected Asset / IP Address:</span></p><p> {vuln['IP(Port)']}</p>
            <p><span class="bold">iii. Detailed Observation:</span> </p><p>{vuln['Description']}</p>
            <p><span class="bold">iv. CVE/CWE:</span> </p><p> {vuln['CVE IDs']}</p>
            <p><span class="bold">v. Severity:</span> </p><p> {vuln['Severity']}</p>
            <p><span class="bold">vi. Recommendation:</span> </p><p> {vuln['Recommendation']}</p>
            <p><span class="bold">vii. Reference:</span> </p><p> {vuln['Reference']}</p>
         """

        if 'New or Repeat observation' in vuln:
            html_content += f"""
            <p><span class="bold">viii. New or Repeat observation:</span> </p><p> {vuln['New or Repeat observation']}</p>
            """
        else:
            html_content += f"""
            <p><span class="bold">viii. New or Repeat observation:</span> </p><p> New</p>
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


# ------------------- GUI Launcher -------------------
def launch_gui():
    root = Tk()
    root.title("Nessus Parser")
    root.geometry("500x300")
    root.config(bg="#f0f0f0")

    # Stylish header
    header_label = Label(root, text="Nessus Parser", font=("Arial", 18, "bold"), bg="#f0f0f0", fg="#333")
    header_label.pack(pady=20)

    # Creator label
    creator_label = Label(root, text="Created with Love by Robin Verma", font=("Arial", 12), bg="#f0f0f0", fg="#555")
    creator_label.pack(pady=5)

    # Select File Button (modern look)
    select_button = Button(root, text="Select Nessus File", command=select_file, width=20, height=2, font=("Arial", 12), bg="#4CAF50", fg="white", relief="raised", bd=3)
    select_button.pack(pady=20)

    # Exit Button
    exit_button = Button(root, text="Exit", command=root.quit, width=20, height=2, font=("Arial", 12), bg="#f44336", fg="white", relief="raised", bd=3)
    exit_button.pack(pady=10)

    root.mainloop()


# ------------------- Main Entry Point -------------------
if __name__ == "__main__":
    launch_gui()