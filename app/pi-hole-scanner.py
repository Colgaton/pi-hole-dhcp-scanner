from flask import Flask, request #import main Flask class and request object
import ipaddress
import sqlite3
from sqlite3 import Error
import subprocess
from pushbullet import Pushbullet
import os
import sys

app = Flask(__name__) #create the Flask app

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
if "PUSHBULLETKEY" not in os.environ:
    print ("Missing Pushbullet Key...")
    sys.exit(2)

pushbulletkey = os.environ['PUSHBULLETKEY']

if "LISTENONLY" in os.environ:
    listenonly = os.environ['LISTENONLY']
    print("Starting in listenonly mode...")
else:
    print("Starting in scanning mode...")
    listenonly = 0

def run_nmap(iptoscan):
    nmapcmd = '/usr/bin/nmap' 
    print ("Running nmap...")
    result = subprocess.run([nmapcmd, iptoscan, "-p", "80"], stdout=subprocess.PIPE)
    return (result.stdout.decode('utf-8'))

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print (e)

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
        print(e)

def insert_record(conn, record):
    sql = """ INSERT INTO ips(name, ip, macaddr, lastchecked, addedin) VALUES (?,?,?,?,?) """
    try:
        c = conn.cursor()
        c.execute(sql,record)
        conn.commit()
    except Error as e:
        print("Error: %s", e)
        return '<P>Error</P>'

    return c.lastrowid

def select_record(conn, macaddr):
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM ips WHERE macaddr=?", (macaddr,))
    except Error as e:
        print("Error select_record: %s", e)
        return '<P>select record error</P>'

    return (len(c.fetchall()))

def send_results(note):

    pb = Pushbullet(pushbulletkey)
    push = pb.push_note("New device detected!", note)

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
        print ("Erro creating conn")
        return '''<h1>Error creating sqlite</h1>'''

    # Check if table does not exist, and creates it
    if check_if_table_exists(conn, database) == 0:
        create_table(conn, sql_create_ip_table)

    rows = select_record(conn, macaddr)

    if rows == 0:
        print("Rows == 0, inserting rows")
        record = ('router',iptoscan,macaddr,'5/4/2020','5/4/2020')
        insert_record(conn, record)
    else:
        print("Mac Address already exists. Number of rows:", rows)

    conn.close()

    if listenonly == 0:
        nmapoutput = run_nmap(iptoscan)
        send_results(nmapoutput)

    return '''<h1>done</h1>'''

if __name__ == '__main__':
    app.run(debug=True, port=5001) #run app in debug mode on port 5001
