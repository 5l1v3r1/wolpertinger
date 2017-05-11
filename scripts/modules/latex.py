# -*- coding: utf-8 -*-

""" Wolpertinger MCP output plugin for Latex output """

from struct import pack, unpack
from socket import inet_aton, inet_ntoa

class WolperOutput():
    """ Wolpertinger MCP output plugin class for Latex output """

    def __init__(self, master):
        """ get cursor from wolper-wcp """

        self.master = master
        self.short_option = "t:"
        self.long_option = "tex="

    def help(self):
        """ return the help line of this plugin """

        return "  -%s, --%s <SCAN#>\t\tProduces latex output" % (self.short_option.rstrip(':'), self.long_option.rstrip('='))

    # this method should be a classmethod
    # pylint: disable=R0201
    def parameter(self, param):
        """ format the plugins parameter """

        return int(param)

    def run(self, ref_id):
        """Show portscan information in LaTeX Format"""

        self.master.open_database()
        hosts = []                                              # host list
        success = False

        # get list of portscans
        self.master.db_cursor.execute(r"select id from scan where id=?",  (int(ref_id), ))
        for row in self.master.db_cursor:
            success = True

        if not success:
            print "Invalid portscan number!"
            return

        # get scanned hosts
        self.master.db_cursor.execute(r"select distinct h.ip from result as r, host as h where scan_id=? and r.host_id=h.id", (int(ref_id),))

        for row in self.master.db_cursor:
            ip = pack("I", row[0])
            hosts.append(ip)

        hosts.sort()
        for i in xrange(len(hosts)):
            hosts[i] = inet_ntoa(hosts[i])
            h = hosts[i]

        # show results for each host
            results = self.get_host_results_tcp(ref_id, h)

            print r'\subsection{System %s (\texttt{NAME})}' % (h, )
            print r'\labelip{%s}' % (h, )
            print
            print r'Bei diesem System handelt es sich um ein \frmtprodname{OS} mit dem Hostnamen \frmtvar{NAME}'
            print
            print r'\subsubsection{Portscan}'
            print
            print r'Ein Portscan mit dem Programm \frmtprodname{Wolpertinger} zeigte die folgenden offenen TCP-Ports:'
            print
            print r'{\footnotesize'
            print r'\begin{Verbatim}[commandchars=\\\{\}]'
            print r'Open TCP ports on %s:' % (h, )

            # print table header
            print "PORT\tSERVICE"
            for r in results:
                print "%d\t%s" % (r[0], r[1])

            print
            print r'\end{Verbatim}'
            print r'}'

    def get_host_results_tcp(self, scan_id, ip):
        """Get portscan results (TCP) of specified host"""

        results = []                                            # result list

        # convert IP address
        ip = unpack("I", inet_aton(ip))[0]

        # get open TCP ports
        if self.master.db_version == '0.7+':
            self.master.db_cursor.execute(r"select r.port, s.name from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port and h.ip=? order by r.port asc", (int(scan_id), ip))
        elif self.master.db_version == '0.8.3+' or self.master.db_version == '0.8.5+':
            self.master.db_cursor.execute(r"select r.port, s.name from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port and r.protocol='TCP' and h.ip=? order by r.port asc", (int(scan_id), ip))

        for row in self.master.db_cursor:
            port = row[0]
            service = row[1]

            # store result in results list
            results.append((port, service))

        return results
