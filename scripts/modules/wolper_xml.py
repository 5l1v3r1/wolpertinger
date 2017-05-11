# -*- coding: utf-8 -*-

""" Wolpertinger MCP output plugin for XML output """

from struct import pack, unpack
from socket import inet_aton, inet_ntoa

class WolperOutput():
    """ Wolpertinger MCP output plugin class for XML output """

    def __init__(self, master):
        """ get cursor from wolper-wcp """

        self.master = master
        self.short_option = "x:"
        self.long_option = "xml="


    def help(self):
        """ return the help line of this plugin """

        return "  -%s, --%s <SCAN#>\t\tProduces XML output" % (self.short_option.rstrip(':'), self.long_option.rstrip('='))


    # this method should be a classmethod
    # pylint: disable=R0201
    def parameter(self, param):
        """ format the plugins parameter """

        return int(param)


    def get_portscan_info(self, ref_id):
        """Get portscan information"""

        self.master.db_cursor.execute(r"select * from scan where id=? order by id asc", (int(ref_id),))

        for row in self.master.db_cursor:
            hosts = row['hosts']                                        # number of scanned hosts
            ports = row['ports']                                        # number of scanned ports
            pps = int(row['pps'])                                       # packets per second
            source_ip = pack("I", row['source_ip'])                     # source IP address
            source_port = row['source_port']                            # source port
            start_time = row['start_time']                              # start time
            end_time = row['end_time']                                  # end time
            tag = row['tag']

            # calculate scan time
            scan_time = end_time - start_time

			# get scan state if database supports it
            if self.master.db_version_or_newer('0.8.5+'):
                status = str(row['status'])
            else:
                status = "UNKNOWN"

        return (hosts, ports, pps, source_ip, source_port, start_time, end_time, scan_time, tag, status)


    def get_portscan_results(self, scan_id):
        """Retrieve results for portscan"""

        results = []                                            # result list

        # get open ports
        self.master.db_cursor.execute(r"select r.port, h.ip, s.name from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port order by h.ip asc, r.port asc", (int(scan_id),))

        for row in self.master.db_cursor:
            port = int(row[0])
            ip = pack("I", row[1])
            service = row[2]

            # store result in results list
            results.append((port, inet_ntoa(ip), service))

        return results


    def get_drones(self, scan_id):
        """Get drones used for portscan"""

        drones = []                                             # drone list

        # get list of portscans
        self.master.db_cursor.execute(r"select d.ip, du.port, du.type from drone as d, drone_usage as du where du.scan_id=? and d.id=du.drone_id order by type", (int(scan_id),))

        for row in self.master.db_cursor:
            ip = pack("I", row['ip'])                              # drone IP address
            port = int(row['port'])                                  # drone port
            typ = int(row['type'])                                   # drone type

            # local mode
            if row[0] == 1 or row[0] == 2:
                drones.append(("local drone", 0, typ))
            else:
                drones.append((inet_ntoa(ip), port, typ))

        return drones


    def run(self, ref_id):
        """Generate XML output"""

        self.master.open_database()

        #scan_id = []                                            # list of scan IDs
        hosts = []                                              # host list
        #rid = int(ref_id) - 1
        #port_str = ""

        success = False

        # get list of portscans
        self.master.db_cursor.execute(r"select id from scan where id =?",  (ref_id, ))
        for row in self.master.db_cursor:
            success = True

        if not success:
            print "Invalid portscan number!"
            return

        # get and show some portscan statistics
        info = self.get_portscan_info(ref_id)

        num_hosts = info[0]                                 # number of scanned hosts
        num_ports = info[1]                                 # number of scanned ports
        pps = info[2]                                       # packets per second
        source_ip = info[3]                                 # source IP address
        #source_port = info[4]                               # source port
        start_time = info[5]                                # start time
        end_time = info[6]                                  # end time
        scan_time = info[7]                                 # scan time
        tag = info[8]                                       # tag
        status = info[9]									# scan state

        # get total portscan results
        total_results = self.get_portscan_results(ref_id)

        # get used drones
        drones = self.get_drones(ref_id)

        # start XML output
        print "<?xml version=\"1.0\" ?>"
        print "<wolpertingerscan tag=\"%s\" state=\"%s\" starttime=\"%d\" endtime=\"%d\" scantime=\"%d\" scanned_hosts=\"%d\" scanned_ports=\"%d\" open_ports=\"%d\" source_ip=\"%s\" pps=\"%d\">" % (tag, status, start_time, end_time, scan_time, num_hosts, num_ports, len(total_results), inet_ntoa(source_ip), pps)
        print "<drones>"
        print "<drone addr=\"%s\" portid=\"%d\" type=\"listener\" />" % (drones[-1][0], drones[-1][1])

        for s in drones[:-1]:
            print "<drone addr=\"%s\" portid=\"%d\" type=\"sender\" />\n" % (s[0], s[1]),

        print "</drones>"

        # get hosts with open ports
        self.master.db_cursor.execute(r"select distinct h.ip from result as r, host as h where scan_id=? and r.host_id=h.id", (ref_id,))

        # get host list
        for row in self.master.db_cursor:
            ip = pack("I", row[0])
            hosts.append(ip)

        hosts.sort()
        for i in xrange(len(hosts)):
            hosts[i] = inet_ntoa(hosts[i])
            h = hosts[i]

        # get list of open ports for each host
            print "<host addr=\"%s\" addrtype=\"ipv4\">" % (h)

            # get open ports
            print "<ports>"

            ip = unpack("I", inet_aton(h))[0]

            if self.master.db_version_or_older('0.7+'):
                self.master.db_cursor.execute(r"select r.port, s.name from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port and h.ip=? order by r.port asc", (int(ref_id), ip))
            elif self.master.db_version_or_newer('0.8.5+'):
                self.master.db_cursor.execute(r"select r.port, s.name from result as r, host as h, services as s where scan_id=? and r.host_id=h.id and r.port=s.port and r.protocol='TCP' and h.ip=? order by r.port asc", (int(ref_id), ip))

            for r in self.master.db_cursor:
                print "<port protocol=\"tcp\" portid=\"%d\" state=\"open\" />" % (r[0])

            print "</ports>"
            print "</host>"

        print "</wolpertingerscan>"
