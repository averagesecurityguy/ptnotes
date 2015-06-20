#!/usr/bin/python
# -*- coding: utf-8 -*-

import sqlite3
import logging
import sys
import os.path
import json

import validate


class Database():
    """
    Class to handle all database interactions.
    """

    def __init__(self):
        """
        Setup the connection and initialize the database.
        """
        self.log = logging.getLogger('DATABASE')
        self.valid = validate.Validate()
        self.con = sqlite3.connect('ptnotes.sqlite')
        self.con.row_factory = sqlite3.Row
        self.cur = self.con.cursor()
        self.initialize_database()
        self.import_attacks()

    def execute_sql(self, stmt, args=None, commit=True):
        """
        Execute an SQL statement.

        Attempt to execute an SQL statement and log any errors. Return True if
        successful and false if not.
        """
        self.log.debug('Executing {0} with args {1}.'.format(stmt, args))

        try:
            if args is None:
                self.cur.execute(stmt)
            else:
                self.cur.execute(stmt, args)

            if commit is True:
                self.con.commit()

            return True

        except sqlite3.Error as e:
            self.log.debug(e)
            return False

    def initialize_database(self):
        """
        Setup the tables we need for our database.
        """
        items = '''
        CREATE TABLE IF NOT EXISTS items (
            id integer primary key autoincrement,
            ip text,
            port integer,
            protocol text,
            note text
        )
        '''
        itable = self.execute_sql(items)

        attacks = '''
        CREATE TABLE IF NOT EXISTS attacks (
            id integer primary key,
            name text
            port integer,
            protocol text,
            description text
        )
        '''
        atable = self.execute_sql(attacks)

        if (itable is False) or (atable is False):
            self.log.critical('Could not create database.')
            sys.exit(1)

    def import_attacks(self):
        """
        Import the known attacks from the attacks.json file in the data
        folder.
        """
        attack_file = os.path.join('data', 'attacks.json')
        try:
            with open(attack_file) as f:
                attacks = json.loads(f.read())

        except (IOError, ValueError):
            self.log.critical('Could not load attack file.')
            sys.exit(1)

        stmt = "INSERT INTO attacks (id, name, description, port, protocol) VALUES(?,?,?,?,?)"
        for a in attacks:
            insert = self.execute_sql(stmt, (a['id'], a['name'], a['description'], a['port'], a['protocol']))
            if insert is False:
                self.log.error('Could not load attack {0}.'.format(a['id']))

    #
    # Manipulate Items
    #
    def create_item(self, ip, port, protocol, note):
        """
        Add new item.
        """
        self.log.debug('Creating new item.')
        try:
            self.valid.ip(ip)
            self.valid.port(port)
            self.valid.protocol(protocol)

        except AssertionError as e:
            self.log.error(e)
            return False

        stmt = "INSERT INTO items (ip, port, protocol, note) VALUES(?,?,?,?)"
        return self.execute_sql(stmt, (ip, port, protocol, note))

    def delete_item(self, iid):
        """
        Delete an item.
        """
        self.log.debug('Deleting item {0}.'.format(iid))
        stmt = "DELETE FROM items WHERE id=?"
        return self.execute_sql(stmt, (iid,))

    def update_item(self, iid, note):
        """
        Update the item.
        """
        self.log.debug('Updating item {0}.'.format(iid))
        stmt = "UPDATE items SET note=? WHERE id=?"
        return self.execute_sql(stmt, (note, iid))

    def get_item(self, iid):
        """
        Get an item.
        """
        self.log.debug('Getting item {0}.'.format(iid))
        stmt = "SELECT * FROM items WHERE id=?"
        if self.execute_sql(stmt, (iid,), commit=False) is True:
            return self.cur.fetchone()
        else:
            return None

    def get_items(self, ip):
        """
        Get all items associated with an IP.
        """
        self.log.debug('Getting all items for {0}.'.format(ip))
        stmt = "SELECT * FROM items WHERE ip=?"

        if self.execute_sql(stmt, (ip,)) is True:
            return self.cur.fetchall()
        else:
            return []

    def get_hosts(self):
        """
        Get all hosts.
        """
        self.log.debug('Getting all hosts.')
        stmt = "SELECT ip FROM items"

        if self.execute_sql(stmt) is True:
            return self.cur.fetchall()
        else:
            return []

    #
    # Manipulate Common Attacks
    #
    def get_attack(self, aid):
        """
        Get an attack and a list of potential targets.
        """
        self.log.debug('Getting attack {0}.'.format(aid))
        stmt = "SELECT * FROM attacks WHERE id=?"
        if self.execute_sql(stmt, (aid,), commit=False) is True:
            attack = self.cur.fetchone()

            stmt = "SELECT * FROM items WHERE port=? AND protocol=?"
            if self.execute_sql(stmt, (attack['port'], attack['protocol']), commit=False) is True:
                hosts = self.cur.fetchall()
                return attack, hosts
            else:
                return None, None
        else:
            return None, None

    def get_attacks(self):
        """
        Get all potential attacks.
        """
        self.log.debug('Getting all potential attacks.')
        stmt = "SELECT name, description FROM attacks"
        if self.execute_sql(stmt, commit=False) is True:
            return self.cur.fetchall()
        else:
            return []
