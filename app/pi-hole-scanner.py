from flask import Flask, render_template, request #import main Flask class and request object
import ipaddress
import sqlite3
from sqlite3 import Error
import subprocess
from pushbullet import Pushbullet
import os
import sys
from datetime import datetime
import requests # for gotify
import re

app = Flask(__name__) #create the Flask app

now = ''
e = ''
database = r"sqlite.db"
sql_create_ip_table = """CREATE TABLE IF NOT EXISTS ips (
                                        id integer PRIMARY KEY,
                                        name text NOT NULL,
                                        ip text NOT NULL,
                                        macaddr text NOT NULL,
                                        lastchecked text NOT NULL,
                                        addedin text NOT NULL
                                    ); """

if "NOTIFICATIONMODE" not in os.environ:
    print ("You have to provide the NOTIFICATIONMODE env var...", file=sys.stderr)
    sys.exit(2)

notificationmode = os.environ['NOTIFICATIONMODE']
listenhost = os.environ['LISTENHOST']

if notificationmode == 'p':
    if not "PUSHBULLETKEY" in os.environ:
        print ("Missing PUSHBULLETKEY...", file=sys.stderr)
        sys.exit(2)
    else:
         pushbulletkey = os.environ['PUSHBULLETKEY']
         print ("Pushbullet enabled...", file=sys.stderr)
elif notificationmode == 'g':
    if not "GOTIFYKEY" or not "GOTIFYURL" in os.environ:
        print ("Missing gotify vars...", file=sys.stderr)
        sys.exit(2)
    else:
        gotifykey = os.environ['GOTIFYKEY']
        gotifyurl = os.environ['GOTIFYURL']
        print ("Gotify enabled...", file=sys.stderr)

if "LISTENONLY" in os.environ:
    listenonly = 1
    print("Starting in listenonly mode...", file=sys.stderr)
else:
    print("Starting in scanning mode...", file=sys.stderr)
    listenonly = 0

def run_nmap(iptoscan):
    nmapcmd = '/usr/bin/nmap' 
    print ("Running nmap...", file=sys.stderr)
    result = subprocess.run([nmapcmd, iptoscan, "-p", "80"], stdout=subprocess.PIPE)
    return (result.stdout.decode('utf-8'))

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print (e, file=sys.stderr)

def check_if_table_exists(conn, database):
    c = conn.cursor()
    c.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name=?", (database,))

    if c.fetchone()[0]==1:
        return 1
    else:
        return 0

def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e, file=sys.stderr)

def insert_record(conn, record):
    sql = """ INSERT INTO ips(name, ip, macaddr, lastchecked, addedin) VALUES (?,?,?,?,?) """
    try:
        c = conn.cursor()
        c.execute(sql,record)
        conn.commit()
    except Error as e:
        print(e, file=sys.stderr)
        return '<P>Error</P>'

    return c.lastrowid

def select_record(conn, macaddr):
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM ips WHERE macaddr=?", (macaddr,))
    except Error as e:
        print("Error select_record:", e, file=sys.stderr)
        return '<P>select record error</P>'

    return (c.fetchall())

def send_results(title,note):

    if notificationmode == 'p':
        pb = Pushbullet(pushbulletkey)
        push = pb.push_note(title, note)
    elif notificationmode == 'g':
        url = ("%s/message?token=%s" % (gotifyurl, gotifykey))
        message = {'title': title, 'message': note }
        rest = requests.post(url, json=message)

@app.route('/search')
def search():
    macaddr = request.args.get('mac')
    if not macaddr:
        return '''<h1>Missing MAC argument</h1>'''

    if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macaddr.lower()):
        return '''<h1>Not a valid MAC Address</h1>'''

    conn = create_connection(database)

    if conn is None:
        print ("Erro creating conn", file=sys.stderr)
        return '''<h1>Error creating sqlite</h1>'''

    try:
        c = conn.cursor()
        #rows = c.execute("SELECT * FROM ips WHERE macaddr=?", (macaddr,))
        c.execute("SELECT * FROM ips WHERE macaddr=?", (macaddr,))
    except Error as e:
        print("Error select_record:", e, file=sys.stderr)
        return '<P>select record error</P>'

    rows = c.fetchall()
    conn.close()
    return render_template("search.html", value=rows)

@app.route('/scan')
def ipscan():
    iptoscan = request.args.get('ip')
    macaddr = request.args.get('mac')
    ips_are_equal = 0

    if not iptoscan:
        return '''<h1>Missing IP argument</h1>'''
    if not macaddr:
        return '''<h1>Missing MAC argument</h1>'''

    try:
        isprivate = ipaddress.ip_address(iptoscan).is_private
    except:
        return '''<h1>Error! IP address is not a valid private IP.</h1>'''

    if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macaddr.lower()):
        return '''<h1>Not a valid MAC Address</h1>'''

    conn = create_connection(database)

    if conn is None:
        print ("Erro creating conn", file=sys.stderr)
        return '''<h1>Error creating sqlite</h1>'''

    # Check if table does not exist, and creates it
    if check_if_table_exists(conn, database) == 0:
        create_table(conn, sql_create_ip_table)

    rows = select_record(conn, macaddr)

    # First time we see this device, so run a scan and send results
    if len(rows) == 0:
        if listenonly == 0:
            nmapoutput = run_nmap(iptoscan)
            send_results("New device detected!", nmapoutput)
        addedin = datetime.now().timestamp()
        record = ('router',iptoscan,macaddr,'5/4/2020',addedin)
        insert_record(conn, record)
    elif len(rows) > 0: # Device is already there, did the IP change?
         for row in rows:
             if row[2] == iptoscan:
                 ips_are_equal = 1 # IP is in the db already, quit
                 break
         if ips_are_equal == 0: # if IP is not in the database, did the device got a new IP?
             if listenonly == 0:
                 print("Did the device change its ip?", file=sys.stderr)
                 send_results("Device with new IP detected!", macaddr)
             addedin = datetime.now().timestamp()
             record = ('router',iptoscan,macaddr,'5/4/2020',addedin)
             insert_record(conn, record)

    conn.close()
    return '''<h1>done</h1>'''

if __name__ == '__main__':
    app.run(debug=True,host=listenhost, port=5001) #run app in debug mode on port 5001
