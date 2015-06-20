#!/usr/bin/env python

import xml.etree.ElementTree
import logging
import os.path

import db


class Import():

    def __init__(self, filename):
        self.log = logging.getLogger('IMPORT')
        self.db = db.Database()
        self.filename = filename
        self.scan_data = self.open_file()
        self.file_type = self.get_file_type(self.scan_data[:100])

        if self.file_type == 'Nessus':
            self.import_nessus()
        elif self.file_type == 'Nmap':
            self.import_nmap()
        else:
            self.log.error('Unknown file type, skipping import.')

    def open_file(self):
        """
        Open the file for import.

        Ensure the file we want to import exists and is a file before we
        open it.
        """
        try:
            with open(self.filename) as file:
                return file.read()

        except IOError as e:
            self.log.error('Unable to open file {0}.'.format(self.filename))
            return ''

    def get_file_type(self, header):
        """
        Determine the source of the scan data.
        """
        self.log.debug('Checking file type with header {0}.'.format(header))
        if '<NessusClientData_v2>' in header:
            return 'Nessus'
        elif 'Nmap' in header:
            return 'Nmap'
        else:
            return 'Unknown'


    def import_nessus(self):
        """
        Load the Nessus scan data into an XML structure and import the data.
        """
        self.log.info('Importing Nessus file.')
        # Load Nessus XML file into the tree and get the root element.
        root = xml.etree.ElementTree.fromstring(self.scan_data)

        for report in root.findall('Report'):
            report_name = report.attrib['name']
            self.log.info('Importing report {0}.'.format(report_name))
            self.process_nessus_hosts(report.findall('ReportHost'))

    def process_nessus_hosts(self, report_hosts):
        """
        Process each host in a report
        """
        self.log.debug('Processing Nessus report hosts.')
        for host in report_hosts:
            self.log.debug('Getting IP address for report host.')
            ip = ''
            for tag in host.find('HostProperties').findall('tag'):
                if tag.attrib['name'] == 'host-ip':
                    ip = tag.text

            if (ip != ''):
                self.log.info('Processing ip {0}.'.format(ip))
                self.process_nessus_items(ip, host.findall('ReportItem'))


    def process_nessus_items(self, ip, report_items):
        """
        Process each report item in a host.
        """
        for item in report_items:
            text = xml.etree.ElementTree.tostring(item, encoding='utf-8')
            self.log.debug('Processing report item {0}.'.format(text))

            port = int(item.attrib['port'])
            if port == 0:
                continue
                
            proto = item.attrib['protocol']
            
            note = ''
            output = item.find('plugin_output')
            if output is not None:
                note = output.text
        
            if self.db.create_item(ip, port, proto, note) is False:
                self.log.error('Unable to create new Nessus item in database.')


    def ip_key(self, ip):
        """
        Return an IP address as a tuple of ints for sorting purposes.
        """
        return tuple(int(part) for part in ip.split('.'))




 







