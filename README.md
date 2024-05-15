# Project OWASP

This project is a Python-based tool that utilizes the OWASP ZAP API to perform security scanning on web applications. It conducts spidering, passive scanning, and active scanning to identify potential vulnerabilities in target web applications.

## How to Use

### Prerequisites

- Python 3.x
- OWASP ZAP (Zed Attack Proxy)
- Python modules: `zapv2`, `tabulate`

### Installation

1. Install OWASP ZAP from [the official website](https://www.zaproxy.org/download/).
2. Install Python modules using pip:

    ```bash
    pip install zapv2 tabulate
    ```

### Usage

1. **Prepare Targets**: Create a CSV file named `targets.csv` containing the list of target hostnames under the header `target_hostnames`. Each target hostname should be listed on a separate line.

    Example `targets.csv`:

    ```csv
    target_hostnames
    www.mahindra.com
    www.bharti.com
    www.gailonline.com
    www.powergridindia.com
    www.ultratechcement.com
    www.itcportal.com
    www.npci.org.in
    ```

2. **Run the Script**: Execute the `ProjectOwasp.py` script. This script will perform scanning for each target specified in the `targets.csv` file.

    ```bash
    python ProjectOwasp.py
    ```

3. **View Reports**: After the script execution completes, navigate to the `reports` folder. You will find individual text files (`report1.txt`, `report2.txt`, etc.) containing the scan results for each target.

## Note

- Ensure that OWASP ZAP is running and accessible before executing the script.
- Make sure to review and interpret the scan results carefully, as the tool provides information about potential vulnerabilities that may require further investigation or action.
