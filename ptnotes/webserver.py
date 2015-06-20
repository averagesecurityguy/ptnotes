# -*- coding: utf-8 -*-

import flask

import importscan
import db


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
    hosts = sorted(db.items())

    return flask.render_template('hosts.html', hosts=hosts)


@app.route('/host/<ip>')
def get_host(ip):
    """
    Get all the information about a host.
    """
    data = db.get_item(ip)

    return flask.render_template('host.html', host=ip, data=data)


@app.route("/attacks")
def attacks():
    """
    Get a list of all the built in attacks.
    """
    attacks = sorted(db.get_attacks())

    return flask.render_template('attacks.html', attacks=attacks)


@app.route('/attacks/<aid>')
def get_attack(aid):
    """
    Get list of all the hosts possibly vulnerable to the attack.
    """
    hosts = db.get_attack(aid)

    return flask.render_template('attack.html', hosts=hosts)


@app.route('/import', methods=['GET', 'POST'])
def import_scan():
    message = None

    if flask.request.method == 'POST':
        importscan.Import(flask.request.form('filename'))
        message = 'Import of {0} is complete.'

    return flask.render_template('import.html', message=message)
