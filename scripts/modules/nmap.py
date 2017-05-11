# -*- coding: utf-8 -*-

""" Wolpertinger MCP output plugin for NMap input compatible output """

from struct import pack
from socket import inet_ntoa

class WolperOutput():
    """ Wolpertinger MCP output plugin class for NMap input compatible output """

    def __init__(self, master):
        """ get cursor from wolper-wcp """

        self.master = master
        self.short_option = "n:"
        self.long_option = "nmap="

    def help(self):
        """ return the help line of this plugin """

        return "  -%s, --%s <SCAN#>\t\tProduces output which can be used as input for nmap" % (self.short_option.rstrip(':'), self.long_option.rstrip('='))

    # this method should be a classmethod
    # pylint: disable=R0201
    def parameter(self, param):
        """ format the plugins parameter """

        return int(param)

    def run(self, ref_id):
        """Generate NMAP Output"""

        self.master.open_database()
        #scan_id = []                                            # list of scan IDs
        hosts = []                                              # host list
        #rid = int(ref_id) - 1
        port_str = ""

        success = False

        # get list of portscans
        self.master.db_cursor.execute(r"select id from scan where id =?",  (ref_id, ))
        for row in self.master.db_cursor:
            success = True

        if not success:
            print "Invalid portscan number!"
            return

        # get hosts with open ports
        self.master.db_cursor.execute(r"select distinct h.ip from result as r, host as h where scan_id=? and r.host_id=h.id", (ref_id,))

        print "=== NMAP Hostlist ==="

        for row in self.master.db_cursor:
            ip = pack("I", row[0])
            hosts.append(ip)

        hosts.sort()
        for i in xrange(len(hosts)):
            hosts[i] = inet_ntoa(hosts[i])
            print hosts[i]

        # show uniq open TCP ports
        if self.master.db_version == '0.7+':
            self.master.db_cursor.execute(r"SELECT DISTINCT r.port from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port order by r.port asc", (ref_id,))
        elif self.master.db_version == '0.8.3+' or self.master.db_version == '0.8.5+':
            self.master.db_cursor.execute(r"SELECT DISTINCT r.port from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port and r.protocol='TCP' order by r.port asc", (ref_id,))

        print "\n=== NMAP TCP-Portstring ==="

        for r in self.master.db_cursor:
            if port_str == "":
                port_str = str(r[0])
            else:
                port_str = port_str+","+str(r[0])

        print port_str
