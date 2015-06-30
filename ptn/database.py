#!/usr/bin/python
# -*- coding: utf-8 -*-

import sqlite3
import logging
import sys
import os.path
import json
import random

import validate

#
# Initialize the database once when we import the module.
#
PRJ_FILE = os.path.join('data', 'projects.sqlite')
ATK_FILE = os.path.join('data', 'attacks.json')


class Database():
    """
    Class to handle all database interactions.
    """

    def __init__(self, filename):
        """
        Setup the connection and initialize the database.
        """
        self.log = logging.getLogger('DATABASE')
        self.valid = validate.Validate()
        self.filename = filename
        self.con = sqlite3.connect(self.filename)
        self.con.row_factory = sqlite3.Row
        self.cur = self.con.cursor()

    def __del__(self):
        """
        Clean up the database connection if it exists.
        """
        if self.con is not None:
            self.con.close()

    def get_tables(self):
        """
        Get a list of tables in the database.
        """
        stmt = "SELECT name FROM sqlite_master WHERE type='table'"
        if self.execute_sql(stmt) is True:
            return [n['name'] for n in self.cur.fetchall()]
        else:
            return []

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


class ScanDatabase(Database):
    """
    Class to handle scan data and attack notes.
    """
    def __init__(self, filename):
        Database.__init__(self, filename)

    def initialize_scan_database(self):
        """
        Create a new scan database.
        """
        #
        # Define our SQL statements
        #
        items = '''
        CREATE TABLE IF NOT EXISTS items (
            id integer primary key autoincrement,
            ip text,
            port integer,
            protocol text,
            note text
        )
        '''
        ires = self.execute_sql(items)

        attacks = '''
        CREATE TABLE IF NOT EXISTS attacks (
            id integer primary key autoincrement,
            name text,
            port integer,
            protocol text,
            description text,
            note text
        )
        '''
        ares = self.execute_sql(attacks)

        if (ires is False) or (ares is False):
            self.log.critical('Could not initialize database: {0}.'.format(self.filename))
            return False

        #
        # Load our attacks from the JSON file.
        #
        try:
            with open(ATK_FILE) as f:
                attacks = json.loads(f.read())

        except (IOError, ValueError) as e:
            self.log.critical('Could not load attack file: {0}'.format(e))
            return False

        #
        # Insert the attacks into the database.
        #
        put = "INSERT INTO attacks (name, description, port, protocol) VALUES(?,?,?,?)"
        get = "SELECT name FROM attacks WHERE port=? AND protocol=?"

        for a in attacks:
            self.execute_sql(get, (a['port'], a['protocol']), commit=False)
            if self.cur.fetchone() is None:
                self.cur.execute(put, (a['name'], a['description'], a['port'], a['protocol']))
            else:
                self.log.error('Could not load attack {0}.'.format(a['name']))

        return True

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

    def get_items(self, ip):
        """
        Get all items associated with an IP.
        """
        self.log.debug('Getting all items for {0}.'.format(ip))
        stmt = "SELECT * FROM items WHERE ip=? ORDER BY port"

        if self.execute_sql(stmt, (ip,)) is True:
            return self.cur.fetchall()
        else:
            return []

    def get_hosts(self):
        """
        Get all hosts.
        """
        self.log.debug('Getting all hosts.')
        stmt = "SELECT DISTINCT ip FROM items ORDER BY ip"

        if self.execute_sql(stmt) is True:
            return self.cur.fetchall()
        else:
            return []

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
        stmt = "SELECT id, name, description FROM attacks"
        if self.execute_sql(stmt, commit=False) is True:
            return self.cur.fetchall()
        else:
            return []

    def update_attack(self, aid, note):
        """
        Update the attack note.
        """
        self.log.debug('Updating attack {0}.'.format(aid))
        stmt = "UPDATE attacks SET note=? WHERE id=?"
        return self.execute_sql(stmt, (note, aid))

    def get_stats(self):
        """
        Get host and attack stats for the database.
        """
        hosts = len(self.get_hosts())
        attacks = len(self.get_attacks())

        return 'Hosts: {0}  Attacks {1}'.format(hosts, attacks)

class ProjectDatabase(Database):
    """
    Keep track of projects and the database names associated with them.
    """
    def __init__(self):
        Database.__init__(self, PRJ_FILE)
        tables = self.get_tables()
        self.log.debug('TABLES: {0}'.format(tables))
        if not ('projects' in tables):
            self.initialize_project_database()

    def initialize_project_database(self):
        """
        Create a new project database.
        """
        #
        # Define our SQL statements
        #
        projects = '''
        CREATE TABLE IF NOT EXISTS projects (
            id integer primary key autoincrement,
            name text,
            dbfile text
        )
        '''
        res = self.execute_sql(projects)

        if res is False:
            self.log.critical('Could not initialize project database.')
            return False

        return True

    def create_project(self, name):
        """
        Add new project.
        """
        self.log.debug('Creating new project.')
        db_name = ''.join([random.choice('0123456789abcdef') for _ in range(12)])
        db_name = os.path.join('data', db_name + '.sqlite')

        scan_db = ScanDatabase(db_name)
        if scan_db.initialize_scan_database() is True:
            stmt = "INSERT INTO projects (name, dbfile) VALUES(?,?)"
            return self.execute_sql(stmt, (name, db_name))
        else:
            return False

    def get_project(self, pid):
        """
        Get the project name and database file associated with the pid.
        """
        self.log.debug('Getting project for {0}.'.format(pid))
        stmt = "SELECT name, dbfile FROM projects WHERE id=?"

        if self.execute_sql(stmt, (pid,)) is True:
            return self.cur.fetchone()
        else:
            return None, None

    def get_projects(self):
        """
        Get all projects.
        """
        self.log.debug('Getting all projects.')
        stmt = "SELECT * FROM projects ORDER BY name"

        if self.execute_sql(stmt) is True:
            return self.cur.fetchall()
        else:
            return []

    def update_project(self, pid, name):
        """
        Update the project name.
        """
        self.log.debug('Updating project {0}.'.format(pid))
        stmt = "UPDATE projects SET name=? WHERE id=?"
        return self.execute_sql(stmt, (name, pid))

    def delete_project(self, pid):
        """
        Delete the project and the associated database file.
        """
        self.log.debug('Deleting project {0}.'.format(pid))
        name, db_file = self.get_project(pid)
        if name is None:
            self.log.error('Could not find project {0}.'.format(pid))

        stmt = "DELETE FROM projects WHERE id=?"
        if self.execute_sql(stmt, (pid,)) is True:
            self.delete_file(db_file)
        else:
            self.error('Could not delete project {0} from database.'.format(pid))

    def delete_file(self, filename):
        """
        Delete the specified file.
        """
        try:
            os.remove(filename)
        except Exception as e:
            self.log.error('Could not delete file {0}: {1}'.format(filename, e))
