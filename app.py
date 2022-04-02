from flask import Flask, render_template, request, session, redirect
from flask_sqlalchemy import SQLAlchemy
from os import getenv
import logging

'''
These are part of the autoindex, should be removed or commented out.
Autoindex shows all the files and directories in the root 
A6:2017-Security Misconfiguration and/or A9:2017-Using Components with Known Vulnerabilities
'''

import os.path # Should be removed or commented out.
from flask_autoindex import AutoIndex # Should be removed or commented out.

app = Flask(__name__)

# Part of autoindex, should be removed or commented out.
# A6:2017-Security Misconfiguration and/or A9:2017-Using Components with Known Vulnerabilities.
AutoIndex(app, browse_root=os.path.curdir)

app.config["SQLALCHEMY_DATABASE_URI"] = getenv("DATABASE_URL")
db = SQLAlchemy(app)
app.secret_key = getenv("SECRET_KEY")

'''
This logs too sensitive and too much.
A3:2017-Sensitive Data Exposure
Options; removing or commenting out or changing level to logging.CRITICAL.
Logs are stored to the applications directory.
Because Autoindex is in use, the logs are available for everyone to view.
'''
logging.basicConfig(filename="logs.log", level=logging.DEBUG, format = f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

@app.route("/index")
def index():
    return render_template("index.html")

def get_notes_by_user_id(user_id):
    sql = "SELECT content FROM notes WHERE user_id=:user_id"
    result = db.session.execute(sql, {"user_id": user_id})
    notes = result.fetchall()
    db.session.commit()
    return notes

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    
    '''
    This is vulnerable to SQL-injection: A1:2017-INJECTION
    For example when writing ' UNION SELECT * FROM Users -- to the username field you can log in to the app.
    Although it is not a legitimate username and lets you log in without a legitimate password.
    '''    
    
    sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    result = db.session.execute(sql)

    '''
    The upper should be removed and replaced with the following which is SQL-Injection proof.
    Uses parametrised queries.
    sql = "SELECT * FROM users WHERE username=:username AND password=:password"
    result = db.session.execute(sql, {"username":username, "password":password})
    '''

    user = result.fetchone()
    if not user:
        return render_template("error.html", error="The given username does not exist.")
    else:
        session["username"] = username
        session["id"] = user[0]
        notes = get_notes_by_user_id(session["id"])

        # Logs sensitive information! A3:2017-Sensitive Data Exposure
        # Passwords and session data should not be logged.
        app.logger.info('Logged in succesfully with username %s, password %s, session id %s and session username %s', username, password, username, username)
        return render_template("notes.html", notes=notes)

@app.route("/create")
def show_create_view():
    return render_template("new_user.html")

@app.route("/echo")
def show_funny_form():
    return render_template("funny_form.html")

@app.route("/send_funny_form", methods=["POST"])
def show_funny_form_result():
    content = request.form["echo"]

    # XSS vulnerability: A7:2017-Cross Site Scripting.
    return "You wrote the following text: " + content

    '''
    Should use Flask's own render_templates which prevent this vulnerability.
    For example:
    return render_template("echo_template.html", text_to_be_shown=content)
    '''

@app.route("/add_note")
def show_new_note_view():
    return render_template("new_note.html")

@app.route("/create_note", methods=["POST"])
def create_new_note():
    '''
    This is vulnerable to CSRF, because the application is not checking that is the request really coming from
    the user who is logged in.
    This could be prevented for example like this:
    1.) For every succesful login, create a secret csrf-token like this:
        a.) session["csrf_token"] = secrets.token_hex(16)
    2.) For every form which does a POST-method, include an hidden input where the session csrf-token is applied
        b.)<input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
    3.) In the route which handles the route, check that the token is valid for the user:
        c.) if session["csrf_token"] != request.form["csrf_token"]: abort(403)
        HTTP status-code 403 means forbidden.
    '''

    content = request.form["note"]
    sql = "INSERT INTO notes (content, removed, user_id) VALUES (:content, false, :user_id )"
    db.session.execute(sql, {"content":content, "removed": False, "user_id": session["id"]})
    db.session.commit()

    notes = get_notes_by_user_id(session["id"])

    # Logs sensitive information. A3:2017-Sensitive Data Exposure
    app.logger.info('%s created new note succesfully with content %s', session["username"], content)
    return render_template("notes.html", notes=notes)

@app.route("/createuser", methods=["POST"])
def create_new_user():
    username = request.form["username"]
    password = request.form["password"]

    '''
    Password is not hashed and there is no minimun requirements:
    e.g. minimum of 8 letters with atleast 1 number and 1 special character or equivalent.
    A2:2017-Broken Authentication
    can be fixed for example using werkzeug-library with create_password_hash and check_password_hash functions
    '''

    sql = "INSERT INTO users (username, password, admin) VALUES (:username, :password, :admin)"
    db.session.execute(sql, {"username":username, "password":password, "admin": False})
    db.session.commit()

    '''
    Logs sensitive information! A3:2017-Sensitive Data Exposure
    Password or admin status info should not be logged.
    '''

    app.logger.info('Created new user succesfully with username %s and password %s and no admin rights', username, password)
    return redirect('/index')

@app.route("/logout", methods=["POST"])
def logout():
    del session["username"]
    del session["id"]
    return redirect('/index')

@app.route("/admin_panel_login")
def show_admin_view():
    return render_template("admin_login.html")

@app.route("/admin_view", methods=["POST"])
def view():
    return render_template("admin_panel.html")

@app.route("/notes")
def show_notes():
    notes = get_notes_by_user_id(session["id"])
    return render_template("notes.html", notes=notes)

@app.route("/show_admin_view", methods=["GET","POST"])
def admin_login():
    username = request.form["username"]
    password = request.form["password"]
    sql = "SELECT * FROM users WHERE username=:username AND password=:password AND admin=true"
    result = db.session.execute(sql, {"username":username, "password":password})
    user = result.fetchone()
    if not user:
        return render_template("error.html", error="User does not have admin privileges. Please contact the application support.")
    else:
        session["username"] = username
        session["id"] = username

        # Logs sensitive information!
        # A3:2017-Sensitive Data Exposure
        app.logger.info('Logged in succesfully with username %s, password %s, session id %s and session username %s and has admin rights', username, password, username, username)
        return render_template("admin_panel.html")
