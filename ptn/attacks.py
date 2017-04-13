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
    def __init__(self, project_file):
        self.db = database.ScanDatabase(project_file)
        self.log = logging.getLogger('ATTACK')
        self.attacks = self.load_attacks(ATK_FILE)

    def load_attacks(self, filename):
        """
        Load attacks from JSON file.
        """
        attacks = []

        self.log.info('Loading attack file.')
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
            self.log.info('Finding attacks for {0}.'.format(a['name']))
            items = self.get_items(a)

            if items != []:
                # If the attack does not exist, create it. If it does exist then
                # add hosts to it.
                attack = self.db.get_attack_by_name(a['name'])
                if attack is None:
                    self.db.create_attack(a['name'], a['description'], items)
                else:
                    self.db.update_attack_hosts(attack['id'], items)

    def get_items(self, attack):
        """
        Get all items matching the attack data.
        """
        self.log.debug('Getting items for {0}.'.format(attack['name']))
        items = []

        items.extend(self.db.get_items_by_keywords(attack.get('keywords')))

        self.log.debug('Found {0} total items.'.format(len(items)))

        items = ["{0}:{1}:{2}".format(i[0], i[1], i[2]) for i in items]

        return items
