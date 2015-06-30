# -*- coding: utf-8 -*-

import flask
from functools import wraps
import logging

import database
import importscan


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
    data = db.get_items(ip)

    return flask.render_template('host.html', host=ip, data=data)


@app.route('/attack/<aid>', methods=['GET', 'POST'])
@project_required
def get_attack(aid):
    """
    Get list of all the hosts possibly vulnerable to the attack.
    """
    db = database.ScanDatabase(project_file)

    if flask.request.method == 'POST':
        note = flask.request.form['note']
        db.update_attack(aid, note)

    attack, hosts = db.get_attack(aid)

    return flask.render_template('attack.html', attack=attack, hosts=hosts)


@app.route('/import/<pid>', methods=['POST'])
def import_scan(pid):
    """
    Import scan data into the database associated with the pid.
    """

    # Get our project
    pdb = database.ProjectDatabase()
    project = pdb.get_project(pid)

    i = importscan.Import(project['dbfile'])
    scans = flask.request.files.getlist("scans[]")

    for scan in scans:
        i.import_scan(scan.read())

    return flask.redirect(flask.url_for('get_project', pid=pid))


@app.route('/projects', methods=['GET', 'POST'])
def projects():
    """
    Get a list of all projects.
    """
    pdb = database.ProjectDatabase()

    if flask.request.method == 'POST':
        name = flask.request.form['project_name']
        pdb.create_project(name)

    projects = pdb.get_projects()
    for project in projects:
        db = database.ScanDatabase(project['dbfile'])
        project['stats'] = db.get_stats()

    return flask.render_template('projects.html', projects=projects)


@app.route('/project/<pid>')
def get_project(pid):
    """
    Get a project, including the list of hosts attacks.
    """
    pdb = database.ProjectDatabase()
    project = pdb.get_project(pid)

    # Set the project file globally
    global project_file
    project_file = project['dbfile']

    if project_file is None:
        return flask.redirect(flask.url_for('projects'))
    else:
        db = database.ScanDatabase(project_file)
        hosts = db.get_hosts()
        attacks = db.get_attacks()

        return flask.render_template('project.html', pid=pid, project=project['name'], 
                                     hosts=hosts, attacks=attacks)

@app.route('/project/<pid>/delete')
def delete_project(pid):
    """
    Delete the specified project.
    """
    pdb = database.ProjectDatabase()
    project = pdb.delete_project(pid)

    return flask.redirect(flask.url_for('projects'))
