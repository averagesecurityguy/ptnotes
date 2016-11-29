# -*- coding: utf-8 -*-

import flask
from functools import wraps
import logging

import database
import importscan
import attacks


#-----------------------------------------------------------------------------
# WEB SERVER
#-----------------------------------------------------------------------------
app = flask.Flask(__name__)
project_file = None


def project_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logging.debug('Project File: {0}'.format(project_file))
        if project_file is None:
            return flask.redirect(flask.url_for('projects'))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
    return flask.render_template('index.html')


@app.route("/about")
def about():
    return flask.render_template('about.html')


@app.route('/host/<ip>')
@project_required
def host(ip):
    """
    Get all the information about a host.
    """
    db = database.ScanDatabase(project_file)
    data = db.get_host(ip)

    if data is None:
        flask.abort(404)

    return flask.render_template('host.html', host=ip, data=data)


@app.route('/item/<item_id>')
@project_required
def item(item_id):
    """
    Get all the information about an item.
    """
    db = database.ScanDatabase(project_file)
    item = db.get_item(item_id)

    if item is None:
        flask.abort(404)

    return flask.render_template('item.html', item=item)

@app.route('/attack/<aid>', methods=['GET', 'POST'])
@project_required
def get_attack(aid):
    """
    Get list of all the hosts possibly vulnerable to the attack.
    """
    db = database.ScanDatabase(project_file)

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        db.update_attack_note(aid, note)

    attack = db.get_attack(aid)

    if attack is None:
        flask.abort(404)

    items = [i.split(':') for i in attack['items'].split(',')]

    return flask.render_template('attack.html', attack=attack, items=items)


@app.route('/import/<pid>', methods=['GET', 'POST'])
def import_scan(pid):
    """
    Import scan data into the database associated with the pid.
    """

    if flask.request.method == 'GET':
        return flask.render_template('import.html', pid=pid)

    else:
        # Get our project
        pdb = database.ProjectDatabase()
        project = pdb.get_project(pid)

        if project is None:
            flask.abort(404)

        i = importscan.Import(project['dbfile'])
        scans = flask.request.files.getlist("scans[]")

        for scan in scans:
            i.import_scan(scan.read())

        a = attacks.Attack(project['dbfile'])
        a.find_attacks()

        return flask.redirect(flask.url_for('get_project', pid=pid))

@app.route('/notes/<pid>')
def notes(pid):
    """
    Display all attack notes.
    """
    # Get our project
    pdb = database.ProjectDatabase()
    project = pdb.get_project(pid)

    if project is None:
        flask.abort(404)

    db = database.ScanDatabase(project['dbfile'])
    notes = db.get_attack_notes()

    return flask.render_template('notes.html', notes=notes)

@app.route('/projects', methods=['GET', 'POST'])
def projects():
    """
    Get a list of all projects.
    """
    pdb = database.ProjectDatabase()
    stats = {}

    if flask.request.method == 'POST':
        name = flask.request.form['project_name']
        pdb.create_project(name)

    projects = pdb.get_projects()
    for project in projects:
        db = database.ScanDatabase(project['dbfile'])
        stats[project['id']] = db.get_stats() 

    return flask.render_template('projects.html', projects=projects, stats=stats)


@app.route('/project/<pid>')
def get_project(pid):
    """
    Get a project, including the list of hosts attacks.
    """
    pdb = database.ProjectDatabase()
    project = pdb.get_project(pid)

    if project is None:
        flask.abort(404)

    ports = {}

    # Set the project file globally
    global project_file
    project_file = project['dbfile']

    if project_file is None:
        return flask.redirect(flask.url_for('projects'))
    else:
        db = database.ScanDatabase(project_file)
        hosts = db.get_hosts()
        attacks = db.get_attacks()

        for host in hosts:
            ip = host['ip']
            port_list = db.get_ports(ip)
            ports[ip] = [str(p['port']) for p in port_list if p['port'] != 0]

        return flask.render_template('project.html', pid=pid,
                                     project=project['name'], hosts=hosts,
                                     ports=ports, attacks=attacks)

@app.route('/project/<pid>/delete')
def delete_project(pid):
    """
    Delete the specified project.
    """
    pdb = database.ProjectDatabase()
    project = pdb.delete_project(pid)

    return flask.redirect(flask.url_for('projects'))


@app.errorhandler(404)
def page_not_found(e):
    return flask.render_template('404.html'), 404


@app.errorhandler(500)
def inernal_error(e):
    return flask.render_template('500.html'), 500
