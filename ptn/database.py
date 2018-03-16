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

def ip_key(ip):
    return tuple(int(part) for part in ip.split('.'))


class DatabaseException(Exception):
    pass

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

    def execute_sql(self, stmt, args=None, commit=False):
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


class ScanDatabase():
    """
    Class to handle scan data and attack notes.
    """
    def __init__(self, filename):
        self.log = logging.getLogger('DATABASE')
        self.itemdb = ItemDatabase(filename)
        self.attackdb = AttackDatabase(filename)
        self.hostdb = HostDatabase(filename)
        self.importdb = ImportDatabase(filename)

    def get_stats(self):
        """
        Get host and attack stats for the database.
        """
        self.log.debug('Gathering stats.')

        hosts = len(self.itemdb.get_unique_hosts())
        attacks = len(self.attackdb.get_attacks())

        return 'Hosts: {0}  Attacks {1}'.format(hosts, attacks)

    def get_host_details(self, ip):
        """
        Get all information associated with an IP.
        """
        host = {'note': '', 'items': []}

        host['note'] = self.hostdb.get_host_note(ip)
        host['items'] = self.itemdb.get_items_by_ip(ip)

        return host

    def get_summary(self):
        """
        Get summary information for all of the hosts.
        """
        summary = []

        hosts = self.itemdb.get_unique_hosts()
        for host in hosts:
            h = dict(self.hostdb.get_host(host))

            ports = self.itemdb.get_ports_by_ip(host)
            h['tcp'] = [str(p) for p in sorted(ports['tcp'])]
            h['udp'] = [str(p) for p in sorted(ports['udp'])]

            summary.append(h)

        summary = sorted(summary, key=lambda x: ip_key(x['ip']))

        return summary

    def get_unique(self):
        unique = {}

        ips = [ip for ip in self.itemdb.get_unique_hosts()]
        unique['ip'] = sorted(ips, key=lambda x: ip_key(x))

        ports = self.itemdb.get_unique_ports()
        unique['tcp'] = [str(p) for p in sorted(ports['tcp'])]
        unique['udp'] = [str(p) for p in sorted(ports['udp'])]

        return unique


class ItemDatabase(Database):
    """
    Class to handle item data.
    """
    def __init__(self, filename):
        Database.__init__(self, filename)

        items = '''
        CREATE TABLE IF NOT EXISTS items (
            id integer primary key autoincrement,
            ip text,
            port integer,
            protocol text,
            note text,
            hash text
        )
        '''
        ires = self.execute_sql(items, commit=True)

        if ires is False:
            raise DatabaseException('Could not create items table.')

    def create_item(self, ip, port, protocol, note, hash):
        """
        Add new item.
        """
        self.log.debug('Creating new item.')
        try:
            self.valid.ip(ip)
            self.valid.port(port)
            self.valid.protocol(protocol)
            self.valid.hash(hash)

        except AssertionError as e:
            self.log.error(e)
            return False

        stmt = "INSERT INTO items (ip, port, protocol, note, hash) VALUES(?,?,?,?,?)"
        return self.execute_sql(stmt, (ip, port, protocol, note, hash), True)

    def get_item(self, item_id):
        """
        Get all items associated with an item_id.
        """
        self.log.debug('Getting information for item {0}.'.format(item_id))
        stmt = "SELECT * FROM items WHERE id=?"

        if self.execute_sql(stmt, (item_id,)) is True:
            return self.cur.fetchone()
        else:
            return {}

    def get_unique_hosts(self):
        """
        Get unique hosts listed in the item database.
        """
        self.log.debug('Getting unique hosts.')
        stmt = "SELECT DISTINCT ip FROM items ORDER BY ip"

        if self.execute_sql(stmt) is True:
            return [h['ip'] for h in self.cur.fetchall()]
        else:
            return []

    def get_unique_ports(self):
        """
        Get unique ports in the database.
        """
        ports = {'tcp': [], 'udp': []}

        self.log.debug('Getting unique TCP ports from the database.')
        stmt = """SELECT DISTINCT(port) FROM items
                  WHERE port != 0 AND protocol == 'tcp'
                  ORDER BY port ASC"""

        if self.execute_sql(stmt) is True:
            ports['tcp'] = [h['port'] for h in self.cur.fetchall()]

        self.log.debug('Getting unique UDP ports from the database.')
        stmt = """SELECT DISTINCT(port) FROM items
                  WHERE port != 0 AND protocol == 'udp'
                  ORDER BY port ASC"""

        if self.execute_sql(stmt) is True:
            ports['udp'] = [h['port'] for h in self.cur.fetchall()]

        return ports

    def get_ports_by_ip(self, ip):
        """
        Get unique TCP and UDP ports associated with an IP.
        """
        ports = {}

        self.log.debug('Getting unique TCP ports for {0}.'.format(ip))
        stmt = """SELECT DISTINCT(port) FROM items
                  WHERE port != 0 AND protocol == 'tcp'
                  AND ip == ?
                  ORDER BY port ASC"""

        if self.execute_sql(stmt, (ip,)) is True:
            ports['tcp'] = [h['port'] for h in self.cur.fetchall()]

        self.log.debug('Getting unique UDP ports for {0}.'.format(ip))
        stmt = """SELECT DISTINCT(port) FROM items
                  WHERE port != 0 AND protocol == 'udp'
                  AND ip == ?
                  ORDER BY port ASC"""

        if self.execute_sql(stmt, (ip,)) is True:
            ports['udp'] = [h['port'] for h in self.cur.fetchall()]

        return ports

    def get_items_by_ip(self, ip):
        """
        Get all items associated with a host.
        """
        self.log.debug('Getting items for host {0}.'.format(ip))
        stmt = "SELECT * FROM items WHERE ip=?"

        if self.execute_sql(stmt, (ip,)) is True:
            return self.cur.fetchall()
        else:
            return []

    def get_items_by_hash(self, hash):
        """
        Return a list of hosts with the specified hash.
        """
        self.log.debug('Getting items associated with hash {0}.'.format(hash))

        stmt = "SELECT ip FROM items WHERE hash=?"
        if self.execute_sql(stmt, (hash,)) is True:
            return [i['ip'] for i in self.cur.fetchall()]
        else:
            return []

    def get_items_by_keywords(self, keywords):
        """
        Return a list of items with the specified keywords.
        """
        if keywords is None:
            return []
        else:
            self.log.debug('Getting items associated with keywords {0}.'.format(','.join(keywords)))

            stmt = "SELECT id, ip, port FROM items WHERE "
            stmt += ' OR '.join(["note LIKE ?" for i in xrange(len(keywords))])
            kw_strs = tuple(['%{0}%'.format(kw) for kw in keywords])

            if self.execute_sql(stmt, kw_strs) is True:
                return [(i['id'], i['ip'], i['port']) for i in self.cur.fetchall()]
            else:
                return []


class AttackDatabase(Database):
    """
    Class to handle attack data.
    """
    def __init__(self, filename):
        Database.__init__(self, filename)

        attacks = '''
        CREATE TABLE IF NOT EXISTS attacks (
            id integer primary key autoincrement,
            name text,
            description text,
            items text,
            note text
        )
        '''
        ares = self.execute_sql(attacks, commit=True)

        if ares is False:
            raise DatabaseException('Could not create attack table.')

    def create_attack(self, name, description, items):
        """
        Create a new attack in the database.
        """
        self.log.debug('Creating new attack for {0}.'.format(name))

        stmt = "INSERT INTO attacks (name, description, items, note) VALUES(?,?,?,?)"
        return self.execute_sql(stmt, (name, description, ','.join(items), ''), True)

    def get_attack_by_name(self, name):
        """
        Get an attack id by name.
        """
        self.log.debug('Getting attack id for {0}.'.format(name))

        stmt = "SELECT id, note FROM attacks WHERE name=?"
        if self.execute_sql(stmt, (name, ), commit=False) is True:
            return self.cur.fetchone()
        else:
            return None

    def get_attack(self, aid):
        """
        Get an attack and a list of potential targets.
        """
        self.log.debug('Getting attack {0}.'.format(aid))

        stmt = "SELECT * FROM attacks WHERE id=?"
        if self.execute_sql(stmt, (aid,), commit=False) is True:
            return self.cur.fetchone()
        else:
            return None

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

    def get_attack_notes(self):
        """
        Get all attack notes.
        """
        self.log.debug('Getting notes for all attacks.')

        stmt = "SELECT name, note FROM attacks"
        if self.execute_sql(stmt, commit=False) is True:
            return [(a['name'], a['note']) for a in self.cur.fetchall()]
        else:
            return []

    def update_attack_hosts(self, aid, items):
        """
        Update the attack items.
        """
        self.log.debug('Updating items for attack {0}.'.format(aid))

        stmt = "UPDATE attacks SET items=? WHERE id=?"
        return self.execute_sql(stmt, (','.join(items), aid), True)

    def update_attack_note(self, aid, note):
        """
        Update the attack note.
        """
        self.log.debug('Updating note for attack {0}.'.format(aid))

        stmt = "UPDATE attacks SET note=? WHERE id=?"
        return self.execute_sql(stmt, (note, aid), True)


class HostDatabase(Database):
    """
    Class to handle host data.
    """
    def __init__(self, filename):
        Database.__init__(self, filename)

        hosts = '''
        CREATE TABLE IF NOT EXISTS hosts (
            id integer primary key autoincrement,
            ip text,
            os text,
            fqdn text,
            note text
        )
        '''
        hres = self.execute_sql(hosts, commit=True)

        if hres is False:
            raise DatabaseException('Could not create hosts table.')

    def create_host(self, ip, os, fqdn):
        """
        Create a new host identified by the IP address.
        """
        self.log.debug('Creating new host for {0}.'.format(ip))

        stmt = "INSERT INTO hosts (ip, os, fqdn) VALUES(?,?,?)"
        return self.execute_sql(stmt, (ip, os, fqdn), True)

    def get_host(self, ip):
        """
        Get host data associated with ip.
        """
        self.log.debug('Getting host data for {0}.'.format(ip))
        stmt = "SELECT ip, os, fqdn FROM hosts WHERE ip=?"

        if self.execute_sql(stmt, (ip,)) is True:
            return self.cur.fetchone()
        else:
            return {}

    def get_host_ip(self, ip):
        """
        Return the host if it exists in the database.
        """
        self.log.debug('Getting host record associated with IP {0}.'.format(ip))

        stmt = "SELECT ip FROM hosts WHERE ip=? LIMIT=1"
        if self.execute_sql(stmt, (ip,)) is True:
            return [i['ip'] for i in self.cur.fetchall()]
        else:
            return []

    def get_host_notes(self):
        """
        Get all notes for hosts.
        """
        self.log.debug('Getting all host notes.')
        stmt = "SELECT ip, note from hosts ORDER BY ip"

        if self.execute_sql(stmt) is True:
            return self.cur.fetchall()
        else:
            return []

    def get_host_note(self, ip):
        """
        Get notes for the specified host.
        """
        self.log.debug('Getting notes for {0}.'.format(ip))
        stmt = "SELECT note from hosts WHERE ip=?"

        if self.execute_sql(stmt, (ip,)) is True:
            return self.cur.fetchone()['note']
        else:
            return ""

    def update_host_note(self, ip, note):
        """
        Update the host note.
        """
        self.log.debug('Updating note for host {0}.'.format(ip))

        stmt = "UPDATE hosts SET note=? WHERE ip=?"
        return self.execute_sql(stmt, (note, ip), True)


class ImportDatabase(Database):
    """
    Class to handle import data.
    """
    def __init__(self, filename):
        Database.__init__(self, filename)

        imports = '''
        CREATE TABLE IF NOT EXISTS imports (
            id integer primary key autoincrement,
            filename text
        )
        '''
        ires = self.execute_sql(imports, commit=True)

        if ires is False:
            raise DatabaseException('Could not create imports table.')

    def get_imported_files(self):
        """
        Get all imported files for the specified project id.
        """
        self.log.debug('Getting all imported files.')
        stmt = "SELECT filename FROM imports ORDER BY filename"

        if self.execute_sql(stmt) is True:
            return [p['filename'] for p in self.cur.fetchall()]
        else:
            return []

    def add_import_file(self, filename):
        """
        Add a filename to the table of imported files for a project.
        """
        self.log.debug('Adding imported file {0}.'.format(filename))

        stmt = "INSERT INTO imports (filename) VALUES (?)"
        return self.execute_sql(stmt, (filename,), True)


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
        projects = '''
        CREATE TABLE IF NOT EXISTS projects (
            id integer primary key autoincrement,
            name text,
            note text,
            dbfile text
        )
        '''
        res = self.execute_sql(projects, commit=True)

        if res is False:
            raise DatabaseException('Could not initialize project database.')

    def create_project(self, name):
        """
        Add new project.
        """
        self.log.debug('Creating new project.')
        db_name = ''.join([random.choice('0123456789abcdef') for _ in range(12)])
        db_name = os.path.join('data', db_name + '.sqlite')

        try:
            scan_db = ScanDatabase(db_name)
            stmt = "INSERT INTO projects (name, dbfile) VALUES(?,?)"
            return self.execute_sql(stmt, (name, db_name), True)
        except DatabaseException:
            return False

    def get_project(self, pid):
        """
        Get the project name and database file associated with the pid.
        """
        self.log.debug('Getting project for {0}.'.format(pid))
        stmt = "SELECT name, dbfile, note FROM projects WHERE id=?"

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

    def update_project_note(self, pid, note):
        """
        Update the project notes.
        """
        self.log.debug('Updating project {0}.'.format(pid))
        stmt = "UPDATE projects SET note=? WHERE id=?"
        return self.execute_sql(stmt, (note, pid), True)

    def delete_project(self, pid):
        """
        Delete the project and the associated database file.
        """
        self.log.debug('Deleting project {0}.'.format(pid))
        name, db_file, _ = self.get_project(pid)
        if name is None:
            self.log.error('Could not find project {0}.'.format(pid))

        stmt = "DELETE FROM projects WHERE id=?"
        if self.execute_sql(stmt, (pid,), True) is True:
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
