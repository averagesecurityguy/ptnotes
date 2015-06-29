import xml.etree.ElementTree
import logging

import database
import errors


class Import():

    def __init__(self, db_file):
        self.log = logging.getLogger('IMPORT')
        self.db = database.ScanDatabase(db_file)

    def import_scan(self, scan_data):
        file_type = self.get_file_type(scan_data[:100])

        try:
            if file_type == 'Nessus':
                self.import_nessus(scan_data)
            elif file_type == 'Nmap':
                self.import_nmap(scan_data)
            else:
                self.log.error('Unknown file type, skipping import.')
                return 'Failed'

        except (errors.ScanImportError):
            self.log.error('Failed to parse scan file.')
            return 'Failed'

        return 'Succeeded'

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

    def import_nessus(self, scan_data):
        """
        Load the Nessus scan data into an XML structure and import the data.
        """
        self.log.info('Importing Nessus file.')
        # Load Nessus XML file into the tree and get the root element.
        try:
            root = xml.etree.ElementTree.fromstring(scan_data)

            for report in root.findall('Report'):
                report_name = report.attrib['name']
                self.log.info('Importing report {0}.'.format(report_name))
                self.process_nessus_hosts(report.findall('ReportHost'))

        except xml.etree.ElementTree.ParseError:
            self.log.error('Unable to parse Nessus XML file.')
            raise errors.ScanImportError

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

            # Deal with low-risk and higher vulnerabilities
            severity = int(item.attrib['severity'])
            self.log.debug('Severity: {0}'.format(severity))
            if severity == 0:
                continue

            port = int(item.attrib['port'])
            proto = item.attrib['protocol']

            note = ''
            description = item.find('description')
            output = item.find('plugin_output')
            if output is not None:
                note = output.text.strip('\n')
            else:
                note = description.text

            if self.db.create_item(ip, port, proto, note) is False:
                self.log.error('Unable to create new Nessus item in database.')
