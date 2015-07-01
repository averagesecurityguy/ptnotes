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
        elif '<!DOCTYPE nmaprun>' in header:
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

            note = '--{0}--\n\n'.format(item.attrib['pluginID'])
            description = item.find('description')
            output = item.find('plugin_output')
            if output is not None:
                note = note + output.text.strip('\n')
            else:
                note = note + description.text

            if self.db.create_item(ip, port, proto, note) is False:
                self.log.error('Unable to create new Nessus item in database.')

    def import_nmap(self, scan_data):
        """
        Load the Nmap scan data into an XML structure and import the data.
        """
        self.log.info('Importing Nmap file.')
        # Load Nmap XML file into the tree and get the root element.
        try:
            root = xml.etree.ElementTree.fromstring(scan_data)

            for host in root.findall('host'):
                self.log.debug('Getting IP address for host.')
                address = host.find('address')
                ip = address.attrib['addr']

                self.log.info('Processing ip {0}.'.format(ip))
                self.process_nmap_ports(ip, host.findall('ports/port'))
                self.process_nmap_hostscripts(ip, host.findall('hostscript/script'))

        except xml.etree.ElementTree.ParseError:
            self.log.error('Unable to parse Nmap XML file.')
            raise errors.ScanImportError

    def process_nmap_ports(self, ip, nmap_ports):
        """
        Process each port in a host.
        """
        for nmap_port in nmap_ports:
            text = xml.etree.ElementTree.tostring(nmap_port, encoding='utf-8')
            self.log.debug('Processing port {0}.'.format(text))

            # Skip any ports that are not open
            if nmap_port.find('state').attrib['state'] != 'open':
                continue

            port = int(nmap_port.attrib['portid'])
            proto = nmap_port.attrib['protocol']

            # Create new item based on the service entry.
            note = self.note_from_nmap_service(nmap_port.find('service'))
            if self.db.create_item(ip, port, proto, note) is False:
                self.log.error('Unable to create new Nmap item in database.')

            # Create new item based on each script entry.
            for script in nmap_port.findall('script'):
                note = self.note_from_nmap_script(script)
                if self.db.create_item(ip, port, proto, note) is False:
                    self.log.error('Unable to create new Nmap item in database.')

    def process_nmap_hostscripts(self, ip, scripts):
        """
        Process each of the host scripts.
        """
        for script in scripts:
            text = xml.etree.ElementTree.tostring(script, encoding='utf-8')
            self.log.debug('Processing host script {0}.'.format(text))

            # Create new item based on each script entry.
            for script in scripts:
                note = self.note_from_nmap_script(script)
                if self.db.create_item(ip, 0, 'tcp', note) is False:
                    self.log.error('Unable to create new Nmap item in database.')

    def note_from_nmap_service(self, service):
        """
        Build the note from the service information.
        """
        note = ''

        if service is None:
            return note

        if service.attrib.get('ostype') is not None:
            note += 'Operating System: {0}\n'.format(service.attrib.get('ostype', ''))

        if service.attrib.get('product') is not None:
            note += 'Service: {0}'.format(service.attrib.get('product', ''))
        else:
            note += 'Service: {0}'.format(service.attrib.get('name', ''))

        if service.attrib.get('extrainfo') is not None:
            note += 'Sevice Info: {0}'.format(service.attrib.get('extrainfo', ''))

        return note


    def note_from_nmap_script(self, script):
        """
        Build the note from the script information.
        """
        note = '--{0}--\n\n'.format(script.attrib.get('id', ''))

        if script.attrib.get('output') is not None:
            note += 'Output: {0}\n'.format(script.attrib.get('output', ''))

        # Get Details
        details = ''
        for table in script.findall('table'):
            tn = table.attrib.get('key')
            for elem in table.findall('elem'):
                key = elem.attrib.get('key')
                val = elem.text

                if tn is not None:
                    details += '{0}: '.format(tn.capitalize())
                if key is not None:
                    details += '{0}: '.format(key.capitalize())
                
                details += '{0}\n'.format(val)

        for elem in script.findall('elem'):
            key = elem.attrib.get('key')
            val = elem.text

            if key is not None:
                details += '{0}: '.format(key.capitalize())
            
            details += '{0}\n'.format(val)

        if details != '':
            note += 'Details:\n{0}'.format(details)

        return note
