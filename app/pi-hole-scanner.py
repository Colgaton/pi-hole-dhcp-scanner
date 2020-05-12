from flask import Flask, request #import main Flask class and request object
import ipaddress
import sqlite3
from sqlite3 import Error
import subprocess
from pushbullet import Pushbullet
import os
import sys
from datetime import datetime
import requests # for gotify

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
    listenonly = os.environ['LISTENONLY']
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

    return (len(c.fetchall()))

def send_results(note):

    if notificationmode == 'p':
        pb = Pushbullet(pushbulletkey)
        push = pb.push_note("New device detected!", note)
    elif notificationmode == 'g':
        url = ("%s/message?token=%s" % (gotifyurl, gotifykey))
        message = {'title': 'New device detected!', 'message': note }
        rest = requests.post(url, json=message)

@app.route('/scan')
def ipscan():
    iptoscan = request.args.get('ip')
    macaddr = request.args.get('mac')

    if not iptoscan:
        return '''<h1>Missing IP argument</h1>'''
    if not macaddr:
        return '''<h1>Missing MAC argument</h1>'''

    try:
        isprivate = ipaddress.ip_address(iptoscan).is_private
    except:
        return '''<h1>Error! IP address is not a valid private IP.</h1>'''

    conn = create_connection(database)

    if conn is None:
        print ("Erro creating conn", file=sys.stderr)
        return '''<h1>Error creating sqlite</h1>'''

    # Check if table does not exist, and creates it
    if check_if_table_exists(conn, database) == 0:
        create_table(conn, sql_create_ip_table)

    rows = select_record(conn, macaddr)

    if rows == 0:
        print("Rows == 0, inserting rows", file=sys.stderr)
        addedin = datetime.now().timestamp()
        record = ('router',iptoscan,macaddr,'5/4/2020',addedin)
        insert_record(conn, record)
        if listenonly == 0:
            nmapoutput = run_nmap(iptoscan)
            send_results(nmapoutput)
    else:
        print("Mac Address already exists. Number of rows:", rows)

    conn.close()
    return '''<h1>done</h1>'''

if __name__ == '__main__':
    app.run(debug=True,host=listenhost, port=5001) #run app in debug mode on port 5001
