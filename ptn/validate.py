#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import re

re_hash = re.compile('^[0-9a-f]{64}$')

class Validate():

    def __init__(self):
        self.log = logging.getLogger('VALID')
        self.protocols = ['tcp', 'udp', 'icmp']
        self.min_port = 0
        self.max_port = 65535

    def ip(self, ip):
        """
        Validate the IP address.
        """
        self.log.debug('Validating IP address {0}.'.format(ip))
        try:
            octets = ip.split('.')
            for octet in octets:
                o = int(octet)
                assert (o >= 0) and (o <= 255)

            return True

        except (TypeError, ValueError, AssertionError):
            self.log.error('The IP address must be in dotted quad notation.')
            raise AssertionError('Invalid IP address.')

    def port(self, port):
        self.log.debug("Validating port {0}.".format(port))
        try:
            assert (port >= self.min_port) and (port <= self.max_port)

        except (TypeError, AssertionError):
            self.log.error('Port must be an integer from 0 to 65535')
            raise AssertionError('Invalid port.')

    def protocol(self, protocol):
        self.log.debug('Validating protocol {0}.'.format(protocol))
        try:
            assert protocol in self.protocols

        except AssertionError:
            self.log.error('Protocol must be in {0}.'.format(', '.join(protocols)))
            raise AssertionError('Invalid protocol.')

    def hash(self, hash):
        self.log.debug('Validating hash {0}.'.format(hash))
        try:
            m = re_hash.search(hash.lower())
            assert m is not None

        except AssertionError:
            self.log.error('Hash must be a valid SHA256 hex value.')
            raise AssertionError('Invalid hash.') 
