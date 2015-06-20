#!/usr/bin/python
# -*- coding: utf-8 -*-

import sqlite3
import logging
import sys

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
        self.cur = self.con.cursor()
        self.initialize_database()


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
            service text,
            note text
        )
        '''
        itable = self.execute_sql(items)

        notes = '''
        CREATE TABLE IF NOT EXISTS notes (
            id integer primary key autoincrement,
            port integer,
            protocol text,
            note text
        )
        '''
        ntable = self.execute_sql(notes)

        if (itable is False) or (ntable is False):
            self.log.critical('Could not create database.')
            sys.exit(1)

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

    def get_items(self):
        """
        Get all items.
        """
        self.log.debug('Getting all items.')
        stmt = "SELECT * FROM items"

        if self.execute_sql(stmt) is True:
            return self.cur.fetchall()
        else:
            return []

    #
    # Manipulate Built-in Notes
    #
    def create_note(self, port, protocol, note):
        """
        Add new note.
        """
        self.log.debug('Creating new built-in note.')
        try:
            validate.valid_port(port)
            validate.valid_protocol(protocol)

        except AssertionError as e:
            self.log.error(e)
            return False

        stmt = "INSERT INTO notes (port, protocol, note) VALUES(?,?,?)"
        return self.execute_sql(stmt, (port, protocol, note))

    def delete_note(self, nid):
        """
        Delete a note.
        """
        self.log.debug('Deleting built-in note {0}.'.format(nid))
        stmt = "DELETE FROM notes WHERE id=?"
        return self.execute_sql(stmt, (nid,))

    def update_note(self, nid, note):
        """
        Update a note.
        """
        self.log.debug('Updating built-in note {0}.'.format(nid))
        stmt = "UPDATE notes SET note=? WHERE id=?"
        return self.execute_sql(stmt, (note, nid))

    def get_note(self, nid):
        """
        Get a note.
        """
        self.log.debug('Getting built-in note {0}.'.format(nid))
        stmt = "SELECT * FROM notes WHERE id=?"
        if self.execute_sql(stmt, (nid,), commit=False) is True:
            return self.cur.fetchone()
        else:
            return None

    def get_notes(self):
        """
        Get all notes.
        """
        self.log.debug('Getting all built-in notes.')
        stmt = "SELECT * FROM notes"
        if self.execute_sql(stmt) is True:
            return self.cur.fetchall()
        else:
            return []
