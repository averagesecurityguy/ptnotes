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


def get_project_db(pid):
    """
    Get our project database.
    """
    pdb = database.ProjectDatabase()
    project = pdb.get_project(pid)

    if project is None:
        flask.abort(404)

    return project


@app.route("/")
def index():
    return flask.render_template('index.html')


@app.route("/about")
def about():
    return flask.render_template('about.html')


@app.route('/project/<pid>/host/<ip>', methods=['GET', 'POST'])
def host(pid, ip):
    """
    Get all the information about a host.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        db.update_host_note(ip, note)

    data = db.get_host(ip)

    if data is None:
        flask.abort(404)

    notes = {}
    for item in data['items']:
        key = "{0}/{1}".format(item['port'], item['protocol'])
        if notes.get(key) is None:
            notes[key] = []
            notes[key].append(item['note'])
        else:
            notes[key].append(item['note'])

    keys = sorted(notes.keys(), key=lambda x: int(x.split('/')[0]))

    return flask.render_template('host.html', pid=pid, host=ip, data=notes, keys=keys)


@app.route('/project/<pid>/host/notes')
def host_notes(pid):
    """
    Display all host notes.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])
    notes = db.get_host_notes()

    return flask.render_template('notes.html', pid=pid, notes=notes)


@app.route('/project/<pid>/item/<item_id>')
def item(pid, item_id):
    """
    Get all the information about an item.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])
    item = db.get_item(item_id)

    if item is None:
        flask.abort(404)

    return flask.render_template('item.html', pid=pid, item=item)


@app.route('/project/<pid>/attack/<aid>', methods=['GET', 'POST'])
def get_attack(pid, aid):
    """
    Get list of all the hosts possibly vulnerable to the attack.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        db.update_attack_note(aid, note)

    attack = db.get_attack(aid)

    if attack is None:
        flask.abort(404)

    items = [i.split(':') for i in attack['items'].split(',')]

    return flask.render_template('attack.html', pid=pid, attack=attack, items=items)


@app.route('/project/<pid>/import', methods=['GET', 'POST'])
def import_scan(pid):
    """
    Import scan data into the database associated with the pid.
    """
    if flask.request.method == 'GET':
        return flask.render_template('import.html', pid=pid)

    else:
        project = get_project_db(pid)
        i = importscan.Import(project['dbfile'])
        scans = flask.request.files.getlist("scans[]")

        for scan in scans:
            i.import_scan(scan.read())

        a = attacks.Attack(project['dbfile'])
        a.find_attacks()

        return flask.redirect(flask.url_for('get_project', pid=pid))


@app.route('/project/<pid>/attack/notes')
def attack_notes(pid):
    """
    Display all attack notes.
    """
    project = get_project_db(pid)
    db = database.ScanDatabase(project['dbfile'])
    notes = db.get_attack_notes()

    return flask.render_template('notes.html', pid=pid, notes=notes)


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

    project_list = pdb.get_projects()
    for project in project_list:
        db = database.ScanDatabase(project['dbfile'])
        stats[project['id']] = db.get_stats() 

    return flask.render_template('projects.html', projects=project_list, stats=stats)


@app.route('/project/<pid>')
def get_project(pid):
    """
    Get a project, including the list of hosts attacks.
    """
    project = get_project_db(pid)
    ports = {}

    db = database.ScanDatabase(project['dbfile'])
    hosts = db.get_hosts()
    attacks = db.get_attacks()

    for host in hosts:
        ip = host['ip']
        data = db.get_host(host['ip'])
        ports[ip] = [str(p) for p in data['ports'] if p != 0]

    return flask.render_template('project.html', pid=pid,
                                 note=project['note'], name=project['name'],
                                 hosts=hosts, ports=ports, attacks=attacks)


@app.route('/project/<pid>/notes', methods=['GET', 'POST'])
def project_notes(pid):
    """
    Display all project notes.
    """
    pdb = database.ProjectDatabase()
    project = get_project_db(pid)

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        pdb.update_project_note(pid, note)

        return flask.redirect(flask.url_for('get_project', pid=pid))
    else:
        note = project['note']
        name = project['name']

        return flask.render_template('project_notes.html', pid=pid, name=name, note=note)


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
