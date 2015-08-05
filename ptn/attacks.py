#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import sys
import os.path
import json
import random

import validate
import database

##
# Process all of the attacks in the JSON file and add new attacks to the
# specified project file.
#

ATK_FILE = os.path.join('data', 'attacks.json')

class Attack():
    def __init__(self, db):
        self.db = database.ScanDatabase(project_file)
        self.log = logging.getLogger('ATTACK')
        self.attacks = self.load_attacks(ATK_FILE)

    def load_attacks(self, filename):
        """
        Load attacks from JSON file.
        """
        attacks = []

        try:
            with open(filename) as f:
                attacks = json.loads(f.read())

        except (IOError, ValueError) as e:
            self.log.critical('Could not load attack file: {0}'.format(e))
        
        return attacks

    def find_attacks(self):
        """
        Find all of the potential attacks in the project based on the attacks
        described in the attack file.
        """
        for a in self.attacks:
            hosts = self.get_hosts(a)

            #
            # If we already have an attack with this name and there is a note
            # attached to it, preserve the note.
            attack = db.get_attack_by_name(a['name'])
            if attack is None:
                db.create_attack(a['name'], a['description'], hosts)
            else:
                db.update_attack_hosts(attack['id'], hosts)

    def get_hosts(attack):
        """
        Get all hosts matching the attack data.
        """
        hosts = []

        hosts.extend(db.get_hosts_by_port(a.get('port')))
        hosts.extend(db.get_hosts_by_protocol(a.get('protocol')))
        hosts.extend(db.get_hosts_keywords(a.get('keywords')))

        return list(set(hosts))
