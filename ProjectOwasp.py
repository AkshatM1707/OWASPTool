import os
import time
import csv
from tabulate import tabulate
from zapv2 import ZAPv2
from threading import Thread

def spider_and_passive_scan(zap, target, report_file):
    with open(report_file, 'a') as f:
        f.write('Accessing target {}\n'.format(target))
    zap.urlopen(target)

    with open(report_file, 'a') as f:
        f.write('Spidering and Passive Scanning target {}\n'.format(target))
    scanid = zap.spider.scan(target)
    while int(zap.spider.status(scanid)) < 100:
        with open(report_file, 'a') as f:
            f.write('Spider progress %: {}\n'.format(zap.spider.status(scanid)))
        time.sleep(2)

    with open(report_file, 'a') as f:
        f.write('Spider completed\n')

    while int(zap.pscan.records_to_scan) > 0:
        with open(report_file, 'a') as f:
            f.write('Records to passive scan : {}\n'.format(zap.pscan.records_to_scan))
        time.sleep(2)

    with open(report_file, 'a') as f:
        f.write('Passive Scan completed\n')

def active_scan(zap, target, report_file):
    with open(report_file, 'a') as f:
        f.write('Active Scanning target {}\n'.format(target))
    scanid = zap.ascan.scan(target)
    while int(zap.ascan.status(scanid)) < 100:
        with open(report_file, 'a') as f:
            f.write('Scan progress %: {}\n'.format(zap.ascan.status(scanid)))
        time.sleep(5)

    with open(report_file, 'a') as f:
        f.write('Active Scan completed\n')

def perform_scan(target, report_file):
    zap = ZAPv2(apikey=apikey)
    spider_and_passive_scan(zap, target, report_file)
    active_scan(zap, target, report_file)

# create reports folder
if not os.path.exists('reports'):
    os.makedirs('reports')


targets = []
with open('targets.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        targets.extend(row)

apikey = 'scrgi9f4stlvcbif68d1ln3aib'

# this will use threads
threads = []
for i, target in enumerate(targets, 1):
    report_file = os.path.join('reports', 'report{}.txt'.format(i))
    thread = Thread(target=perform_scan, args=(target, report_file))
    threads.append(thread)
    thread.start()


for thread in threads:
    thread.join()
