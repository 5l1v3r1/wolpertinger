#!/usr/bin/env python2
"""Create Wolpertinger Database"""

import sqlite3
import sys

# default ports = all ports
ports = "1-65535"

# create default port list
portlist = ports.split(',')

# cmd line: $0 [working directory]
if len(sys.argv) < 2:
    working_dir = "."
else:
    working_dir = sys.argv[1]

database = working_dir + "/wolpertinger.db"
service_file = working_dir + "/wolper-services"
sql_file = working_dir + "/wolpertinger.sql"

# connect to database
conn = sqlite3.connect(database)

# get cursor
c = conn.cursor()

print "[*] Create wolpertinger database ...",
sys.stdout.flush()

# drop tables
c.execute(ur"drop table if exists default_ports")
c.execute(ur"drop table if exists drone")
c.execute(ur"drop table if exists drone_usage")
c.execute(ur"drop table if exists drone_credentials")
c.execute(ur"drop table if exists host_table")
c.execute(ur"drop view if exists host")
c.execute(ur"drop table if exists result")
c.execute(ur"drop table if exists scan")
c.execute(ur"drop table if exists services")
c.execute(ur"drop table if exists options")

# create tables
wolpertables = open(sql_file, 'r').read()
c.executescript(wolpertables)

for p in portlist:
    c.execute(ur"insert into default_ports (port_string) values (?)", (p,))

# create services list
f = open(service_file, "r")

service_ports = [] # list of service ports in service list file

for l in f:
    s = l.split()

    if s[1].find("tcp") != -1:

        service_name = s[0]
        service_port = int(s[1].split("/")[0])
        service_description = ur" ".join(s[3:]).replace(ur"'", ur"`")

        service_ports.append(service_port)

        stmt = ur"insert into services (name, port, description) values (?, ?, ?)"
        params =  (service_name, service_port, service_description)

        c.execute(stmt, params)

f.close()

# add ports to services tables which are not in the service list file
service_name = ur""
service_description = ur""

stmt = ur"insert into services (name, port, description) values (?, ?, ?)"
for service_port in range(1, 65536):
    if service_port not in service_ports:
        params = (service_name, service_port, service_description)

        c.execute(stmt, params)


# Save (commit) the changes
conn.commit()

# We can also close the cursor if we are done with it
c.close()

print "done"
