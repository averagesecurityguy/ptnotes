# -*- coding: utf-8 -*-

import flask

import database
import importscan


#-----------------------------------------------------------------------------
# WEB SERVER
#-----------------------------------------------------------------------------
app = flask.Flask(__name__)


@app.route("/")
def index():
    return flask.render_template('index.html')


@app.route("/about")
def about():
    return flask.render_template('about.html')


@app.route("/hosts")
def hosts():
    """
    Get a list of all the hosts and their open ports.
    """
    db = database.Database()
    hosts = sorted(db.get_hosts())

    return flask.render_template('hosts.html', hosts=hosts)


@app.route('/host/<ip>')
def get_host(ip):
    """
    Get all the information about a host.
    """
    db = database.Database()
    data = db.get_items(ip)

    return flask.render_template('host.html', host=ip, data=data)


@app.route("/attacks")
def attacks():
    """
    Get a list of all the built in attacks.
    """
    db = database.Database()
    attacks = sorted(db.get_attacks())

    return flask.render_template('attacks.html', attacks=attacks)


@app.route('/attacks/<aid>')
def get_attack(aid):
    """
    Get list of all the hosts possibly vulnerable to the attack.
    """
    db = database.Database()
    hosts = db.get_attack(aid)

    return flask.render_template('attack.html', hosts=hosts)


@app.route('/import', methods=['GET', 'POST'])
def import_scan():
    message = None

    if flask.request.method == 'POST':
        file = flask.request.files['file']
        importscan.Import(file.read())
        message = 'Import of {0} is complete.'.format(file.name)

    return flask.render_template('import.html', message=message)
