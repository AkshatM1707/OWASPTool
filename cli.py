import click
from owasp_scanner import OWASPScanner
from sql_injection import SQLInjectionToolc

@click.group()
def cli():
    """OWASP Top 10 Vulnerability Scanner CLI"""
    pass

@cli.command()
@click.argument('target_url')
@click.option('--api-key', required=True, help='ZAP API key')
@click.option('--output-dir', default='scan_results', help='Output directory for scan results')
@click.option('--auth-username', help='Username for authenticated scanning')
@click.option('--auth-password', help='Password for authenticated scanning')
@click.option('--custom-policies', help='Path to custom scan policies JSON file')
def scan(target_url, api_key, output_dir, auth_username, auth_password, custom_policies):
    """Perform vulnerability scan on a target URL"""
    scanner = OWASPScanner(api_key, output_dir)
    
    scan_options = {}
    if auth_username and auth_password:
        scan_options['auth'] = {
            'username': auth_username,
            'password': auth_password
        }
    
    if custom_policies:
        with open(custom_policies) as f:
            scan_options['custom_policies'] = json.load(f)
    
    scanner.scan_target(target_url, scan_options)

@cli.command()
@click.argument('target_url')
@click.option('--needle', required=True, help="Unique string indicating successful SQL injection (e.g., 'Welcome')")
@click.option('--user-id', required=True, type=int, help="User ID to extract the password hash for")
def sql_injection(target_url, needle, user_id):
    """Perform automated SQL Injection to extract password hashes"""
    tool = SQLInjectionTool(target_url, needle)
    tool.execute(user_id)

if __name__ == '__main__':
    cli()
