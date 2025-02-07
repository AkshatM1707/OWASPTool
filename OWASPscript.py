
import time
import json
import logging
from datetime import datetime
from pathlib import Path
from zapv2 import ZAPv2
from typing import List, Dict, Optional

class OWASPScanner:
    def __init__(self, api_key: str, output_dir: str = "scan_results"):
        self.zap = ZAPv2(apikey=api_key)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self._setup_logging()
        
    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def scan_target(self, target_url: str, scan_options: Dict = None) -> Dict:
        """
        Perform comprehensive scanning of a target URL with customizable options
        """
        try:
            scan_options = scan_options or {}
            scan_start_time = datetime.now()
            self.logger.info(f'Starting scan of {target_url}')

            # Configure scan policies based on options
            if scan_options.get('custom_policies'):
                self._configure_scan_policies(scan_options['custom_policies'])

            # Authentication handling if credentials provided
            if scan_options.get('auth'):
                self._handle_authentication(target_url, scan_options['auth'])

            
            self._perform_spider_scan(target_url)
            self._perform_passive_scan()
            self._perform_active_scan(target_url)

            
            scan_results = self._generate_report(target_url, scan_start_time)
            self._save_results(target_url, scan_results)

            return scan_results

        except Exception as e:
            self.logger.error(f"Error scanning {target_url}: {str(e)}")
            raise

    def _perform_spider_scan(self, target_url: str):
        self.logger.info(f'Starting spider scan: {target_url}')
        scanid = self.zap.spider.scan(target_url)
        
        while int(self.zap.spider.status(scanid)) < 100:
            self.logger.info(f'Spider progress: {self.zap.spider.status(scanid)}%')
            time.sleep(2)

    def _perform_passive_scan(self):
        self.logger.info('Starting passive scan')
        while int(self.zap.pscan.records_to_scan) > 0:
            self.logger.info(f'Records to passive scan: {self.zap.pscan.records_to_scan}')
            time.sleep(2)

    def _perform_active_scan(self, target_url: str):
        self.logger.info(f'Starting active scan: {target_url}')
        scanid = self.zap.ascan.scan(target_url)
        
        while int(self.zap.ascan.status(scanid)) < 100:
            self.logger.info(f'Active scan progress: {self.zap.ascan.status(scanid)}%')
            time.sleep(5)

    def _generate_report(self, target_url: str, scan_start_time: datetime) -> Dict:
        alerts = self.zap.core.alerts()
        scan_end_time = datetime.now()
        
        return {
            'target_url': target_url,
            'scan_duration': str(scan_end_time - scan_start_time),
            'scan_timestamp': scan_end_time.isoformat(),
            'alerts': self._process_alerts(alerts),
            'summary': self._generate_summary(alerts)
        }

    def _process_alerts(self, alerts: List) -> List[Dict]:
        return [
            {
                'name': alert['name'],
                'risk': alert['risk'],
                'confidence': alert['confidence'],
                'url': alert['url'],
                'description': alert['description'],
                'solution': alert['solution'],
                'references': alert['reference'],
                'owasp_category': self._map_to_owasp_category(alert)
            }
            for alert in alerts
            if 'fuzzed User Agent' not in alert['name']
        ]

    def _save_results(self, target_url: str, results: Dict):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.output_dir / f'scan_{timestamp}_{target_url.replace("://", "_").replace("/", "_")}.json'
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
            
        self.logger.info(f'Results saved to {filename}')

# scanner/cli.py
import click
from .core import OWASPScanner

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

if __name__ == '__main__':
    cli()