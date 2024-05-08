import time
from tabulate import tabulate
from zapv2 import ZAPv2

target = 'http://127.0.0.1'
apikey = 'scrgi9f4stlvcbif68d1ln3aib'

zap = ZAPv2(apikey=apikey)

print('Accessing target {}'.format(target))
zap.urlopen(target)
time.sleep(2)

print('Spidering target {}'.format(target))
scanid = zap.spider.scan(target)
time.sleep(2)
while int(zap.spider.status(scanid)) < 100:
    print('Spider progress %: {}'.format(zap.spider.status(scanid)))
    time.sleep(2)

print('Spider completed')

while int(zap.pscan.records_to_scan) > 0:
    print('Records to passive scan : {}'.format(zap.pscan.records_to_scan))
    time.sleep(2)

print('Passive Scan completed')

print('Active Scanning target {}'.format(target))
scanid = zap.ascan.scan(target)
while int(zap.ascan.status(scanid)) < 100:
    print('Scan progress %: {}'.format(zap.ascan.status(scanid)))
    time.sleep(5)

print('Active Scan completed')

# Extract and format alerts
alerts = zap.core.alerts()
filtered_alerts = []

# Vulnerability codes and their names
vulnerability_mapping = {
    "OWASP_2021_A01": "Broken Access Control",
    "OWASP_2021_A02": "Cryptographic Failures",
    "OWASP_2021_A03": "Injection",
    "OWASP_2021_A04": "Insecure Design",
    "OWASP_2021_A05": "Security Misconfiguration",
    "OWASP_2021_A06": "Vulnerable and Outdated Components ",
    "OWASP_2021_A07": "Identification and Authentication Failures",
    "OWASP_2021_A08": "Software and Data Integrity Failures",
    "OWASP_2021_A09": "Security Logging and Monitoring Failures",
    "OWASP_2021_A10": "Server-Side Request Forgery "
}

for alert in alerts:
    if 'fuzzed User Agent' in alert['name']:
        continue  # Skip this alert

    owasp_vulnerability = ''
    risk_level = alert['risk']
    description = alert['description']

    # Get OWASP vulnerabilities
    for tag, link in alert['tags'].items():
        if 'OWASP' in tag:
            owasp_vulnerability = tag

    # Get vulnerability name from mapping
    vulnerability_name = vulnerability_mapping.get(owasp_vulnerability, "Unknown Vulnerability")

    filtered_alerts.append({
        'Vulnerability Name': vulnerability_name + ' (' + owasp_vulnerability + ')',
        'Risk Level': risk_level,
        'Description': description
    })

# Display filtered alerts in tabular format
print("\nVulnerability Scan Results:")
print(tabulate(filtered_alerts, headers='keys', tablefmt='grid'))
