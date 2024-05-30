import time
import json
from zapv2 import ZAPv2

# Function to perform scanning for a given target URL
def perform_scan(target_url):
    try:
        print(f'Accessing target {target_url}')
        zap.urlopen(target_url)
        time.sleep(2)

        print(f'Spidering target {target_url}')
        scanid = zap.spider.scan(target_url)
        time.sleep(2)
        while int(zap.spider.status(scanid)) < 100:
            print(f'Spider progress %: {zap.spider.status(scanid)}')
            time.sleep(2)

        print('Spider completed')

        while int(zap.pscan.records_to_scan) > 0:
            print(f'Records to passive scan : {zap.pscan.records_to_scan}')
            time.sleep(2)

        print('Passive Scan completed')

        print(f'Active Scanning target {target_url}')
        scanid = zap.ascan.scan(target_url)
        while int(zap.ascan.status(scanid)) < 100:
            print(f'Scan progress %: {zap.ascan.status(scanid)}')
            time.sleep(5)

        print('Active Scan completed')

        # Extract and format alerts
        alerts = zap.core.alerts()
        filtered_alerts = []

        # Vulnerability codes and their names for OWASP 2021
        owasp_2021_vulnerabilities = {
            "OWASP_2021_A01": "Broken Access Control",
            "OWASP_2021_A02": "Cryptographic Failures",
            "OWASP_2021_A03": "Injection",
            "OWASP_2021_A04": "Insecure Design",
            "OWASP_2021_A05": "Security Misconfiguration",
            "OWASP_2021_A06": "Vulnerable and Outdated Components",
            "OWASP_2021_A07": "Identification and Authentication Failures",
            "OWASP_2021_A08": "Software and Data Integrity Failures",
            "OWASP_2021_A09": "Security Logging and Monitoring Failures",
            "OWASP_2021_A10": "Server-Side Request Forgery"
        }

        print("\nVulnerability Scan Results for {}: ".format(target_url))
        print("-" * 70)
        print("{:<30} | {:<10} | {}".format("Vulnerability Name", "Risk Level", "Description"))
        print("-" * 70)

        owasp_vulnerabilities_found = set()

        for alert in alerts:
            if 'fuzzed User Agent' in alert['name']:
                continue  # Skip this alert

            owasp_vulnerability = ''
            risk_level = alert['risk']
            description = alert['description']

            # Get OWASP vulnerabilities
            for tag, link in alert['tags'].items():
                if tag in owasp_2021_vulnerabilities:
                    owasp_vulnerability = tag
                    owasp_vulnerabilities_found.add(owasp_2021_vulnerabilities[tag])
                    break

            if owasp_vulnerability:  # Only include OWASP 2021 vulnerabilities
                filtered_alerts.append({
                    'Vulnerability Name': owasp_2021_vulnerabilities.get(owasp_vulnerability, "Unknown Vulnerability") + ' (' + owasp_vulnerability + ')',
                    'Risk Level': risk_level,
                    'Description': description
                })
                print("{:<30} | {:<10} | {}".format(owasp_2021_vulnerabilities.get(owasp_vulnerability, "Unknown Vulnerability"), risk_level, description))
                print("\n")  # Add space after each vulnerability

        print("-" * 70)

        # Print OWASP Top 10 vulnerabilities found
        if owasp_vulnerabilities_found:
            print("\nOWASP Top 10 Vulnerabilities Found:")
            print(", ".join(owasp_vulnerabilities_found))

        # Save results to a JSON file
        with open(f'zap_scan_results_{target_url.replace("://", "_").replace("/", "_")}.json', 'w') as f:
            json.dump(filtered_alerts, f, indent=4)

        print("\n" * 3)  # Add space for the next site

    except Exception as e:
        print(f"An error occurred while scanning {target_url}: {e}")


# Function to print a large font message
def print_large_font_message(message):
    print("\n" + "=" * 50)
    print(message.center(50))
    print("=" * 50 + "\n")


# Main program

target_urls_file = 'sites.txt'  # File containing list of target URLs, one per line
apikey = 'u0g6h79944nntg4i4bmodk3mg9'  # Your ZAP API key
zap = ZAPv2(apikey=apikey)

try:
    # Read target URLs from file
    with open(target_urls_file, 'r') as file:
        target_urls = file.readlines()
        target_urls = [url.strip() if url.startswith("http") else "http://" + url.strip() for url in target_urls]

    # Perform scanning for each target URL
    for target_url in target_urls:
        print_large_font_message(f"Scanning {target_url}")
        perform_scan(target_url)

except Exception as e:
    print(f"An error occurred: {e}")
