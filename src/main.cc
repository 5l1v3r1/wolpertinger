/*
 * This file is part of the wolpertinger project.
 *
 * Copyright (C) 2003-2009 Christian Eichelmann <ceichelmann@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <getopt.h>

#include <fcntl.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H
#include <netinet/tcp.h>
#define NETINET_TCP_H
#endif

#include <poll.h>
#include <signal.h>

#include "shared.h"
#include "ipc.h"
#include "drone.h"
#include "main.h"
#include "database.h"

drone_list dl; /* praise the magic drone list object */

uint8_t send_child_sync = 0; /* sender process synchronized */
uint8_t recv_child_sync = 0; /* listener process synchronized */

/* scan infos for database backend */
struct info scan_info;

/* global informations */
struct global_informations global;

/* get children sync signals */
void s_child_sync(int arg) {
	send_child_sync = 1;
}

void r_child_sync(int arg) {
	recv_child_sync = 1;
}

/* Catch up SIGINT and clean up */
void sigint(int sig) {
	MSG(MSG_WARN, "caught SIGINT: cleaning up...\n");
	cleanup();
	exit(1);
}

#ifndef NOMAINFUNCTION
int main(int argc, char *argv[]) 
{
	mytime_t start_time, stop_time, est_stop_time;

	uint32_t chld_timeout = 0;
	uint64_t total_ports = 0;
	uint64_t total_pps = 0;
    char *timestr;
	
	/* signal handler for SIGINT */
	signal(SIGINT, sigint);

	/* initialize global */
	bzero(&global, sizeof(struct global_informations));
	
	/* signal handler for children in single mode */
	signal(WOLPER_CHLD_SENDER_SYNC, s_child_sync);	
	signal(WOLPER_CHLD_LISTENER_SYNC, r_child_sync);	

	/* save commandline */
	dl.save_cmd_line(argc, argv);
	
	/* open database */
	db_open();

	/* parse commandline options */
	get_options(argv, argc);

	/* local mode based on unix domain sockets instead of network */
	if (dl.get_local()) {
		MSG(MSG_DBG, "Starting wolpertinger WITHOUT drones. Forking one sender and one listener drone.\n")
		
		/* fork sender/listener drone */
		if (!fork_drones(dl.get_device())) {
			MSG(MSG_ERR, "Could not fork drones (local mode).\n");
		} else {

			/* wait for children to sync */
			chld_timeout = tv2long(NULL) + CHLD_SYNC_TIMEOUT;
			while (send_child_sync  < 1 || recv_child_sync < 1) {
				if (tv2long(NULL) > chld_timeout) {
					MSG(MSG_ERR, "timeout while waiting for childs to SYNC with master\n");
				}
			}

			// let the drones setup the unix domain sockets
			sleep(1);
		}
	}
	
	/* connect to all drones and start challenge response authentication */
	if (!dl.connect_and_authenticate()) {
		MSG(MSG_ERR, "can not connect to or authenticate with at least one sender and one listener drone\n");
	}
	
	/* clear screen */
	cls();
	gotoxy (0, 0);
	
	/* print banner */
    timestr = get_time_str();
	MSG(MSG_USR, "Starting %s %s at %s\n", MY_NAME, MY_VERSION, timestr);
    free(timestr);

	/* placeholder for sender statistics */
	MSG(MSG_VBS, "\n\n\n");

	/* send workunits to drones */
	dl.distribute_workunits();
	
	/*  add listener address to scan */
	db_set_listener(dl.get_listener_addr());
	
	/* fill scan_info structure */
	scan_info.num_ports = dl.get_num_ports();
	scan_info.num_hosts = dl.get_num_hosts();
	scan_info.pps = dl.get_pps();
	scan_info.source_port = dl.get_sport();
	scan_info.source_ip = dl.get_listener_addr();
	
	if (scan_info.scan_tag == NULL && global.use_database) {
		printf("[?] enter an identifier for this scan (max. %d characters): ", MAX_TAGNAME_LEN);
		scan_info.scan_tag = (char *) safe_zalloc(MAX_TAGNAME_LEN + 1);
		fgets(scan_info.scan_tag, MAX_TAGNAME_LEN, stdin);

		/* remove newline */
		if(scan_info.scan_tag[strlen(scan_info.scan_tag) - 1] == '\n')
			scan_info.scan_tag[strlen(scan_info.scan_tag) - 1] = '\0';			

		MSG(MSG_VBS, "\n");
		
	}

	/* set savepoint for database rollback when -q flag is used */
	if (!global.use_database) {
		MSG(MSG_DBG, "scan will be removed from database after completion.\n");
		db_set_savepoint();
	}
	
	/* start-time of scan */
    start_time = (mytime_t) time(NULL);
    //MSG(MSG_DBG, "Startime is %u.\n", start_time);

	/* calculate scan time */
    MSG(MSG_DBG, "Scanning %d hosts (%d ports each) with %d retrys, %d sender drones and %d pps.\n", dl.get_num_hosts(), dl.get_num_ports(), dl.get_retry(), dl.get_num_sender_drones(), dl.get_pps());
	total_ports = (((uint64_t)dl.get_num_hosts() * (uint64_t)dl.get_num_ports()) * (uint64_t)dl.get_retry());
	total_pps = ((uint64_t)dl.get_num_sender_drones() * (uint64_t)dl.get_pps());
    //MSG(MSG_DBG, "Total Ports: %u, Total PPS: %u\n", total_ports, total_pps);
		
	est_stop_time = start_time + ( total_ports / total_pps ) + dl.get_timeout();
    //MSG(MSG_DBG, "Estimated Stoptime is %u.\n", est_stop_time);
	//est_stop_time.millitm = start_time.millitm + (((double)(total_ports % total_pps ) / (double)total_pps) * 1000);
	
    timestr = get_scan_duration(start_time, est_stop_time);
	MSG(MSG_USR, " * estimated time for portscan: %s\n", timestr);
    free(timestr);

    /* create scan in database */
	db_create_scan(start_time, est_stop_time, &scan_info);
	
	/* start the scan */
	dl.start_scan();
						
	/* poll drones for events */
	dl.poll_drones();
	
	MSG(MSG_USR, "\nScan results:\n");
	
	/* print results */
	db_create_report(0);
	
    /* end-time of scan */
	stop_time = (mytime_t) time(NULL);
	
	/* close portscan in database */
	db_finish_scan(stop_time);
	
	/* print footer */
    timestr = get_scan_duration(start_time, stop_time);
	MSG(MSG_USR, "\nScan of %d %s on %d %s complete. Scan time: %s\n", dl.get_num_ports(), dl.get_num_ports() > 1 ? "ports" : "port", dl.get_num_hosts(), dl.get_num_hosts() > 1 ? "hosts" : "host", timestr);
    free(timestr);


	/* remove scan from database if -q flag is used */
	if (!global.use_database) 
		db_rollback ();
	
	/* close database */
	db_close();

    if (scan_info.scan_tag != NULL) {
        free(scan_info.scan_tag);
        scan_info.scan_tag = NULL;
    }
	
	return 0;		   
}
#endif

/*
 * parse commandline options
 */
int get_options(char *argv[], int argc) { 
	char arg;
	int option_index=0;
	bool drone_def = false;
    const char allports[] = "1-65535";
	
	FILE *hostlist = NULL;
	FILE *dronelist = NULL;
    FILE *portlist = NULL;
	
	struct option long_options[] = {
		{"help", no_argument, 0, 0},
		{"version", no_argument, 0, 0},
		{"iL", required_argument, 0, 0},
		{"with-tcpops", no_argument, 0, 0},
		{"drone-list", required_argument, 0, 0},
        {"port-list", required_argument, 0, 0},
		{"retry", required_argument, 0, 0},
		{0, 0, 0, 0}
	};

	opterr=1;
	optind=1;

	scan_info.scan_tag = NULL;
	global.use_database = 1;

	while((arg = getopt_long_only(argc,argv,"L:s:p:g:D:t:i:hVvdq",long_options,&option_index)) != EOF) {
		switch(arg) {
		case 0:
			if(strcmp(long_options[option_index].name,"help")==0) {
				help(argv[0]);
				break;
			}
			if(strcmp(long_options[option_index].name,"version")==0) {
				versioninfo();
				break;
			}
			if(strcmp(long_options[option_index].name,"iL")==0) {
				if ( !(hostlist=fopen(optarg, "rb"))  ) {
					perror("open hostlist");
					exit(1);
				}
			}
			if(strcmp(long_options[option_index].name,"drone-list")==0) {
				if ( !(dronelist=fopen(optarg, "rb"))  ) {
					perror("open dronelist");
					exit(1);
				}
			}				
            if(strcmp(long_options[option_index].name,"port-list")==0) {
				if ( !(portlist=fopen(optarg, "rb"))  ) {
					perror("open portlist");
					exit(1);
				}
			}
			if(strcmp(long_options[option_index].name,"with-tcpops")==0) {
				dl.set_tcpops(1);
			}		
			if(strcmp(long_options[option_index].name,"retry")==0) {
				dl.set_retry(atoi(optarg));
			}						
			break;
		case 'D':
			dl.add_dronestr (optarg);
			drone_def = true;
			break;
		case 'V': 
			versioninfo();
			break;
		case 't':
			scan_info.scan_tag = strdup(optarg);
			break;
		case 'i': // interface for drones in local mode
			dl.set_interface(optarg);
			break;
		case 'q':
			global.use_database = 0;
			break;
		case 'g':
			if (!isdigit((int)*optarg)) { MSG(MSG_ERR, "invalid sourceport given.\n"); }
			dl.set_sport(atoi(optarg));
			break;
		case 'p': 				
			if (*optarg == 'a') {
				dl.add_portstr(allports);
			} else {
				if (! dl.add_portstr(optarg)) {
					MSG(MSG_ERR, "invalid port string: %s\n", optarg);
				}
            }
			break;
		case 'v':
			dl.set_verb();
			global.verbose++;
			break;
		case 'L':
			if (!isdigit((int)*optarg)) { MSG(MSG_ERR, "invalid timeout given.\n"); }
			dl.set_timeout(atoi(optarg));
			break;
		case 'd':
			dl.set_debug();
			increase_debuglevel();
			break;
		case 's':
			dl.set_pps(atoi(optarg));
			break;
		case 'h':
		case '?':
			help(argv[0]);
			break;
		}
	}
	
	/* get targets into the drones target array */
	if (hostlist || optind < argc) {
		/* read targets from file */
		if (hostlist) {
			get_hosts_from_file(hostlist);
		} 
		/* get hosts from commandline */
		while (optind < argc) {				
			//printf("num_host: %d [%s]\n", dl.add_hostexp (argv[optind]), argv[optind]);
			dl.add_hostexp(argv[optind++]);
		}
	} else {
		fprintf(stderr, "Nothing to scan? Fine... Goodbye\n");
		exit(0);
	}

	/* read dronelist from file */
	if (dronelist) {
		get_drones_from_file(dronelist);
	}

    /* read portlist from file */
	if (portlist) {
		get_ports_from_file(portlist);
	}
	
	/* check for default values */
	if (!dl.get_num_ports()) {
		MSG(MSG_DBG, "using default TCP ports from database\n");
		dl.add_portstr(db_get_default_tcp_ports());		
	}
	
	if (!dl.get_num_hosts ()) {
		MSG(MSG_ERR, "no valid targets found. exiting.\n"); /* Sollte nie passieren, da das ein paar Zeilen höher abgefangen wird */
	}

	if (!dl.get_sport()) {
		dl.set_sport ((rand () % 2600) + 2000);
		MSG(MSG_DBG, "setting sourceport: %d\n", dl.get_sport());
	}
	
	if (!dl.get_timeout()) {
		MSG(MSG_DBG, "using default timeout: 5 seconds\n");
		dl.set_timeout(5);
	}
	
	if (!dl.get_pps()) {
		MSG(MSG_DBG, "using default packet rate: 300pps\n");
		dl.set_pps(300);
	}	
	
	/* check for local use */
	if (!drone_def && !dronelist) {
        MSG(MSG_DBG, "no drones specified. using configmode: connecting to local drones from config\n");
        
        bool configsucceess = false;
        uint16_t listenerport = 0, senderport = 0;
        char drones[MAX_HOSTNAME_LEN];
        
        MSG(MSG_DBG, "[configmode] trying to read local drones from the file " PATH_CONFIG "\n");
        FILE *conffile = NULL;
	    if ( (conffile=fopen(PATH_CONFIG, "rb")) ) {
	        MSG(MSG_DBG, "[configmode] reading local drones from config file\n");
            if(get_drone_ports_from_file(conffile, &listenerport, &senderport)) {
                MSG(MSG_DBG, "[configmode] succeded reading local drone ports from config file\n");
                configsucceess = true;
            } else {
                MSG(MSG_DBG, "[configmode] could not read local drone ports from config file\n");
            }
		    if ( fclose(conffile) != 0 ) {
		        MSG(MSG_WARN, "[configmode] close config file failed: %s\n", strerror(errno));
	        }
	        conffile = NULL;
        } else {
            MSG(MSG_DBG, "[configmode] could not read config file: %s\n", strerror(errno));
        }

        /* try to connect in config mode */
        if (configsucceess) {
            configsucceess = false;
            if (snprintf(drones, MAX_HOSTNAME_LEN-1, "127.0.0.1:%hu,127.0.0.1:%hu", listenerport, senderport) < 0) {
                MSG(MSG_WARN, "[configmode] could not set local drone string\n");
            } else {
                dl.add_dronestr(drones);
                if (!dl.connect_and_authenticate(true)) {
                    MSG(MSG_DBG, "[configmode] failed to connect to local drones from config\n");
		        } else {
                    MSG(MSG_DBG, "[configmode] success in connecting to local drones from config\n");
                    configsucceess = true;
                }
                dl.quit_all_drones(); // disconnect for now
                if (configsucceess) // but if successfull, ...
                    dl.add_dronestr(drones); // ... we will connect again soon
            }
        }
        
        /* try to connect in old "local" mode */
        if (!configsucceess) {
		    MSG(MSG_DBG, "configmode failed. using localmode and fork drone processes\n");
		    dl.set_local();
		    /* add listener drone */
		    dl.add_drone(IDENT_LISTENER, 0, DEFAULT_PASS);
		    /* add sender_drone */
		    dl.add_drone(IDENT_SENDER, 0, DEFAULT_PASS);
        }
	}
	
	return 0;
}

/*
 * HELP !!1
 */
void help(char *me) {
	printf("usage : %s [options] <targets>\n\n"
		"options:\n"
	    "  -D <drones>       : list of drones like ip:port,ip:port,...\n"
		"  -iL <filename>    : load hosts from file\n"
		"  -s <pps>          : packets per seconds\n"
		"  -p <port str>     : ports to scan (1-1000,2000, etc. a = all ports)\n"
		"  -g <source port>  : set source port for scan\n"
	    "  -L <seconds>      : time to wait after packet are sent\n"
	    "  -t <tagname>      : tag of the scan (identifier)\n"
		"  -d                : debug output\n"
		"  -q                : dont save scan in database\n"
		"  -i <ifname>       : interface used for sending/listening (local mode only)\n"
	    "  -v                : verbose output\n"
		"  -V, --version     : show version number and exit\n"
		"  -h, --help        : this help\n\n"
	    " --drone-list <filename>  : read drones from file\n"
        " --port-list <filename>   : read ports from file (format as above in every line)\n"
	    " --retry <num>            : repeat packet scan <num> times\n"
	    " --with-tcpops            : Send packets with some TCP Options set\n\n"   
		"targets:\n"
		"  hostnames\n"
		"  ipadresses\n"
		"  cidr-notation\n"
	    "  ranges\n"
		"  example: 192.168.2.0/24 www.yahoo.com 192.168.10.222 127.0.0-1.10-20,30-40\n\n", me);
	exit(0);
}

void versioninfo() {
	printf("\n *** %s V. %s *** \n\n",MY_NAME,MY_VERSION); 
	exit(0);
}

void get_hosts_from_file(FILE *fd)
{
	char hostexp[MAX_HOSTNAME_LEN];
	
	uint32_t hostexp_index = 0;
	int32_t ch;
	
	while((ch = getc(fd)) != EOF) {
		if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t' || ch == '\0') {
			if (hostexp_index == 0) continue;
			hostexp[hostexp_index] = '\0';
			dl.add_hostexp(hostexp);
			hostexp_index = 0;
		} else if (hostexp_index < sizeof(hostexp) / sizeof(char) -1) {
			hostexp[hostexp_index++] = (char) ch;
		} else {
			MSG(MSG_ERR, "One of the host_specifications from your input file is too long (> %d chars)\n", (int) sizeof(hostexp));
		}
	}
	
	if (hostexp_index > 0) {
		hostexp[hostexp_index] = '\0';
		dl.add_hostexp(hostexp);
	}

	fclose(fd); 	
	
	return;
}


void get_drones_from_file(FILE *fd)
{
	char drone_entry[MAX_HOSTNAME_LEN];
	
	uint32_t drone_index = 0;
	int32_t ch;
	
	while((ch = getc(fd)) != EOF) {
		if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t' || ch == '\0') {
			if (drone_index == 0) continue;
			drone_entry[drone_index] = '\0';
			dl.add_dronestr(drone_entry);
			drone_index = 0;
		} else if (drone_index < sizeof(drone_entry) / sizeof(char) -1) {
			drone_entry[drone_index++] = (char) ch;
		} else {
			MSG(MSG_ERR, "One of the drone specifications from your input file is too long (> %d chars)\n", (int) sizeof(drone_entry));
		}
	}

	if (drone_index > 0) {
		drone_entry[drone_index] = '\0';
		dl.add_dronestr(drone_entry);
	}
	
	fclose(fd); 	
	
	return;
}


void get_ports_from_file(FILE *fd)
{
	char portentry[MAX_PORTSTRING_LEN];
	
	uint32_t index = 0;
	int32_t ch;
	
	while((ch = getc(fd)) != EOF) {
		if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t' || ch == '\0') {
			if (index == 0) continue;
			portentry[index] = '\0';
			if (! dl.add_portstr(portentry)) {
				MSG(MSG_ERR, "invalid port string: %s\n", portentry);
                exit(1);
			}
			index = 0;
		} else if (index < sizeof(portentry) / sizeof(char) -1) {
			portentry[index++] = (char) ch;
		} else {
			MSG(MSG_ERR, "One of the portlist specifications from your input file is too long (> %d chars)\n", (int) sizeof(portentry));	
		}
	}
	
	if (index > 0) {
		portentry[index] = '\0';
		if (! dl.add_portstr(portentry)) {
			MSG(MSG_ERR, "invalid port string: %s\n", portentry);
            exit(1);
		}
	}
	
	fclose(fd); 	
	
	return;
}

int get_drone_ports_from_file(FILE *fd, uint16_t *listenerport, uint16_t *senderport)
{
    char *s, buff[256];
    int count;
    bool foundlistenerport = false, foundsenderport = false;
    
    if (fd == NULL) return 0;

    // Read next line
    while ((s = fgets (buff, (sizeof buff)-1, fd)) != NULL) {
        // Skip blank lines and comments
        if (buff[0] == '\n' || buff[0] == '\r' || buff[0] == '#')
            continue;
        
        // try to match LISTENER_PORT
        count = sscanf(buff, "LISTENER_PORT='%hu'", listenerport);
        if (count == 1) {
            MSG(MSG_DBG, "[config] read LISTENER_PORT='%hu'\n", *listenerport);
            foundlistenerport = true;
            continue;
        }
        
        // try to match SENDER_PORT
        count = sscanf(buff, "SENDER_PORT='%hu'", senderport);
        if (count == 1) {
            MSG(MSG_DBG, "[config] read SENDER_PORT='%hu'\n", *senderport);
            foundsenderport = true;
            continue;
        }
    }

    if (foundlistenerport && foundsenderport) return 1;
    else return 0;
}


int fork_drones(char* devicestr) {
	bool f_listener = false;
	bool f_sender = false;

	pid_t p_listener;
	pid_t p_sender;
	pid_t sudotest;

	char *newargv[20];
	uint8_t argc = 0;
	char *newenviron[] = { NULL };
	char *command;

	char pidstr[25];
	snprintf(pidstr, 25, "%d", getpid());

	int status;

	if (devicestr == NULL) {
		MSG(MSG_ERR, "Invalid device string to fork drones (local mode). Please check route to target ips.\n")
		return 0;
	}

	if (getuid()) { // oh, we are not root, maybe we can become it...

		MSG(MSG_USR, "Trying to acquire root priviliges via sudo (local mode)...\n");
		
		/* execute sudo -v to request password if needed */
		newargv[argc++] = strdup("sudo");
		newargv[argc++] = strdup("-v");
		newargv[argc] = NULL;
		
		sudotest = fork();
		if (sudotest < 0) {
			MSG(MSG_ERR, "Could not fork: %s\n", strerror(errno));
			goto sudofail;
		} else if (sudotest == 0) {
			if (execvpe("sudo", newargv, newenviron) < 0) {
				MSG(MSG_ERR, "Could not execute %s: %s\n", "sudo", strerror(errno));
			}
		} else { // parent process
			waitpid(sudotest, &status, 0);
			MSG(MSG_DBG, "EXITCODE of sudo -v: %d\n", WEXITSTATUS(status));
			if (WEXITSTATUS(status) != 0) {
				goto sudofail;
			}
		}
		
		/* execute sudo -v -n to check whether the password has been cached */
		newargv[argc++] = strdup("-n");
		newargv[argc] = NULL;

		sudotest = fork();
		if (sudotest < 0) {
			MSG(MSG_ERR, "Could not fork: %s\n", strerror(errno));
			goto sudofail;
		} else if (sudotest == 0) {
			if (execvpe("sudo", newargv, newenviron) < 0) {
				MSG(MSG_ERR, "Could not execute %s: %s\n", "sudo", strerror(errno));
			}
		} else { // parent process
			waitpid(sudotest, &status, 0);
			MSG(MSG_DBG, "EXITCODE of sudo -v -n: %d\n", WEXITSTATUS(status));
			if (WEXITSTATUS(status) != 0) {
				MSG(MSG_ERR, "This might indicate that password caching does not work, which is needed here.\n");
				goto sudofail;
			}
		}

        // free newargv
        for (int i=0; i < argc && i < 20; ++i) {
            free(newargv[i]);
        }
		
		/* start actual commands with sudo -n ... */
		argc = 0;
		command = strdup("sudo");
		newargv[argc++] = strdup("sudo");
		newargv[argc++] = strdup("-n");

	} else { // we are root? cool!

		/* directly call wolperdrone */
		command = strdup(PATH_DRONE);
	}

	newargv[argc++] = strdup(PATH_DRONE);
	newargv[argc++] = strdup("-s");
	newargv[argc++] = strdup("--notify-pid");
	newargv[argc++] = strdup(pidstr);
	newargv[argc++] = strdup("-i");
	newargv[argc++] = strdup(devicestr);
	if (global.debug) newargv[argc++] = strdup("-d");
	if (global.debug > 1) newargv[argc++] = strdup("-d");
	
	if (!f_listener) {
		p_listener = fork();
		if (p_listener == 0) { /* i am the listener */
			newargv[argc++] = strdup("-L");
			newargv[argc] = NULL;
			if (execvpe(command, newargv, newenviron) < 0) {
				MSG(MSG_ERR, "Could not execute %s: %s\n", command, strerror(errno));
			}
		}
		f_listener = true;
	}
	sleep(1); // FIXME: this should give sudo enough time to write the timestamp
	          // otherwise, I sometimes got errors about time stamp from the future
	          // which then would require a new password input...

	if (!f_sender) {
		p_sender = fork();
		if (p_sender == 0) { /* i am the sender */
			newargv[argc++] = strdup("-S");
			newargv[argc] = NULL;
			if (execvpe(command, newargv, newenviron) < 0) {
				MSG(MSG_ERR, "Could not execute %s: %s\n", command, strerror(errno));
			}
		}
		f_sender = true;
	}
	
    // free newargv
    for (int i=0; i < argc && i < 20; ++i) {
        free(newargv[i]);
    }
    free(command);

	return 1;

sudofail:
	MSG(MSG_ERR, "Failed to acquire root priviliges. You can try to run wolpertinger as root or start the drones manually with root rights.\n");
	return 0;
}


void cleanup() {
	mytime_t stop_time;

	/* end-time of scan */
	stop_time = (mytime_t) time(NULL);
	
	/* close portscan in database */
	db_cancel_scan(stop_time);

	/* remove scan from database if -q flag is used */
	if (!global.use_database) 
		db_rollback ();
	
	/* close database */
	db_close();
}


void increase_debuglevel() {
	global.debug++;
}

