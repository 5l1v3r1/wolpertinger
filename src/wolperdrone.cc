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
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/stat.h>

/* ip.h and tcp.h need this stuff for the correct struct */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif

/* BSDI needs this for the correct ip struct */
#undef _IP_VHL

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
/* #include <netinet/ip_icmp.h> */
#include <netinet/ether.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H
#include <netinet/tcp.h>
#define NETINET_TCP_H
#endif

#ifndef NETINET_IP_H
#include <netinet/ip.h>
#define NETINET_IP_H
#endif

#include <pcap.h>
#include <signal.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#undef HAVE_CONFIG_H
#endif

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include <pwd.h>

/* create unique identifier */
#include <uuid/uuid.h>

/* syslog support for daemonised drones */
#include <syslog.h>

#include "ipc.h"
#include "shared.h"
#include "wolperdrone.h"
#include "net.h"

wolperdrone drone;

/* global informations */
struct global_informations global;

void sigint(int sig) 
{
	MSG(MSG_WARN, "caught SIGINT: cleaning up...\n");
	drone.cleanup();
	exit(1);
}

int main(int argc, char *argv[])
{	
	/* initialize global */
	bzero(&global, sizeof(struct global_informations));
	
	/* set signal handler */
	signal(SIGINT, sigint);

	/* syslog support */
	setlogmask(LOG_UPTO(LOG_INFO));
	openlog("wolperdrone", LOG_CONS, LOG_USER);
	
	/* get drone options */
	drone.init_options(argc, argv);
	
	/* this stuff needs superuser privileges */
	drone.rootsetup();	
	
	/* drop privileges */
    if (!drop_priv()) {
        MSG(MSG_WARN, "unable to drop privileges\n");
	} else {
		MSG(MSG_DBG, "successfully droped privileges\n");
	}

	/* wait for master to connect */
	drone.listen();
	
	/* handle ipc communication */
	drone.ipc_loop();
	
	return 0;
}

/* constructor */
wolperdrone::wolperdrone()
{
	this->listener_addr = 0;
	this->myaddr = 0;
	this->pps = 0;
	this->tcpops = 0;
	this->retry = 0;
	this->secret = 0;
	this->timeout = 0;
		
	this->port = 0;
	this->lhost = NULL;
	this->prime_sock = 0;
	this->client_sock = 0;
	this->sport = 0;
	this->datalink_offset = 0;

	this->ports.clear();
	this->targets.clear();

	this->iface = NULL;
	this->username = NULL;
	this->password = NULL;

	/* create uuid */
	uuid_generate(this->drone_id);
	
	this->single = 0;
	this->proto = 0;
	this->type = 0;
	this->debug = 0;
	this->drone_state = STATE_WAIT_FOR_WORK;

	this->pcap = NULL;
	this->ip_handle = 0;
	
	this->notifypid = 0;
}

wolperdrone::~wolperdrone() {
	ip_close(this->ip_handle);
    if (this->iface != NULL) free(this->iface);
    if (this->lhost != NULL) free(this->lhost);
    if (this->username != NULL) free(this->username);
    if (this->password != NULL) free(this->password);
	return;
}

void wolperdrone::init_options(int argc, char *argv[])
{
	char arg;

	bool listener = false;
	bool sender = false;
	bool daemon = false;

	char *l_host = NULL;
	char *l_port = NULL;
	
	int option_index=0;
	
	struct option long_options[] = {
		{"help", no_argument, 0, 0},
		{"keyfile", required_argument, 0, 0},
		{"pidfile", required_argument, 0, 0},
		{"notify-pid", required_argument, 0, 0},
		{0, 0, 0, 0}
	};
	
	opterr=1;
	optind=1;

	/* file with username:password inside */
	FILE *keyfile = NULL;
	
	/* file to write daemon pid to, if in daemon mode */
	FILE *pidfile = NULL;

	while((arg = getopt_long_only(argc,argv,"i:p:dsLSDh",long_options,&option_index)) != EOF) {
		switch(arg) {
		case 0:
			if(strcmp(long_options[option_index].name,"help")==0) {
				help(argv[0]);
				break;
			}
			if(strcmp(long_options[option_index].name,"keyfile")==0) {
				if ( !(keyfile=fopen(optarg, "rb")) ) {
					MSG(MSG_ERR, "open keyfile: %s\n", strerror(errno));
				}
			}
			if(strcmp(long_options[option_index].name,"pidfile")==0) {
				if ( !(pidfile=fopen(optarg, "wb")) ) {
					MSG(MSG_ERR, "open pidfile: %s\n", strerror(errno));
				}
			}
			if(strcmp(long_options[option_index].name,"notify-pid")==0) {
				this->notifypid = (pid_t) strtol(optarg, NULL, 10);
			}
			break;
		case 'i': 
			this->iface = strdup(optarg);
			break;
		case 'p':
			if (strstr(optarg, ":")) {
				l_host = strtok(optarg, ":");
				l_port = strtok(NULL, "");
				this->port = atoi(l_port);
				this->lhost = l_host;
			} else {
				this->port = atoi(optarg);
			}
			break;
		case 'd':
			this->debug++;
			global.debug++;
			break;
		case 's':
			this->single++;
			break;
		case 'L':
			listener = true;
			break;
		case 'S':
			sender = true;
			break;
		case 'D':
			daemon = true;
			global.syslog ++;
			break;
		case 'h':
		case '?':
			help(argv[0]);
			break;
		}
	}

	/* r00t p0w3r r3qu1r3d */
	if (getuid()) {
		printf("only root can run this program.\n");
		exit(0);
	}

	/* validity check */
	if ((listener && sender) || (!listener && !sender)) {
		MSG(MSG_WARN, "no drone type specified\n");
		help(argv[0]);
	}
	
	if (!this->iface) {
		MSG(MSG_WARN, "no interface specified (-i <device>)\n");
		help(argv[0]);
	}
	
	if (!this->port && !this->single) {
		MSG(MSG_WARN, "no local port specified (-p <port>)\n");
		help(argv[0]);
	}

	if ( pidfile != NULL && daemon == false) {
		MSG(MSG_WARN, "pidfile used without deamon mode (-D)\n");
		
		if ( fclose(pidfile) != 0 ) {
			MSG(MSG_ERR, "close pidfile: %s\n", strerror(errno));
		}
		pidfile = NULL;
		
		help(argv[0]);
	}

	/* set drone type */
	this->type = sender ? IDENT_SENDER : IDENT_LISTENER;	

	/* password handling */
	if (this->single) {
		/* set port to zero for singlescan */
		this->port = 0;
		
		/* hardcoded default auth for single scan */
		this->username = strdup(DEFAULT_USER);
		this->password = strdup(DEFAULT_PASS);
	} else {	
		/* get username and password from stdin */
		this->username = (char *) safe_zalloc (MAX_USERNAME_LEN + 1);
		this->password = (char *) safe_zalloc (MAX_PASSWORD_LEN + 1);
		
		if (keyfile == NULL) {
			fprintf(stderr, "Enter username for this drone (max. %d characters) : ", MAX_USERNAME_LEN);
			fgets(this->username, MAX_USERNAME_LEN, stdin);
		
			/* remove newline */
			if(this->username[strlen(this->username) - 1] == '\n')
				this->username[strlen(this->username) - 1] = 0;	

			fprintf(stderr, "Enter password for this drone (max. %d characters) :", MAX_PASSWORD_LEN);
			strncpy(this->password, getpass(" "), MAX_PASSWORD_LEN);
		} else {
			/* read username and password from keyfile */
			get_userpass_from_file(keyfile, this->username, this->password);
			
			if ( fclose(keyfile) != 0 ) {
				MSG(MSG_ERR, "close keyfile: %s\n", strerror(errno));
			}
			keyfile = NULL;
		}
	}

	/* whats my adress? */
	this->myaddr = this->get_device_addr();	
	if (!this->myaddr) {
		MSG(MSG_ERR, "device %s has no usable adress, check interface config\n", this->iface);		
	}
	if (this->type == IDENT_LISTENER) this->listener_addr = this->myaddr;

	/* daemonize? */
	if (daemon) {
 		pid_t pid, sid;
		
		syslog(LOG_INFO, "Starting the daemonizing process");
	 
		pid = fork();

		if (pid < 0) {
			MSG(MSG_ERR, "Failed to daemonize drone: %s\n", strerror(errno));
		}

		/* parent process */
		if (pid > 0) {
			
			/* write pid to pidfile */
			if (pidfile != NULL) {
				fprintf(pidfile,"%ju\n",(uintmax_t) pid);
				
				if ( fclose(pidfile) != 0 ) {
					MSG(MSG_ERR, "close pidfile: %s\n", strerror(errno));
				}
				pidfile = NULL;
			}
			
			/* exit parent process */
			exit(EXIT_SUCCESS);
		}
		
		 /* Change the file mode mask */
		umask(0);
		
		/* Create a new SID for the child process */
		sid = setsid();
		if (sid < 0) {
	        /* Log any failure here */
	        exit(EXIT_FAILURE);
		}
		
		/* Change the current working directory */
		if ((chdir("/")) < 0) {
			MSG(MSG_ERR, "Failed to create process group: %s\n", strerror(errno));
		}
		
		/* Close out the standard file descriptors */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}
	
	return;
}


void wolperdrone::rootsetup(void)
{

	/* the following preparations should still be done with superuser rights */

    if (this->type == IDENT_LISTENER) {
	    /* create pcap handler */
    	this->pcap = init_pcap(this->iface);
	}
        
    if (this->type == IDENT_SENDER) {
		/* create ip handler */
		this->ip_handle = ip_open();
	}
	
	/* open IPC socket on specified port */
	this->prime_sock = open_ipc_socket(this->port, this->type, this->lhost);
	
	/* send sync signal to parent process if this is local mode */
	if (this->single) {
		if (this->notifypid == 0) {
			this->notifypid = getppid();
			MSG(MSG_DBG, "Single mode without notify-pid option, signaling to parent process instead.\n");
		}
		MSG(MSG_DBG, "Sending notification signal to process with PID %d.\n", this->notifypid);
		if (this->type == IDENT_LISTENER) kill(this->notifypid, WOLPER_CHLD_LISTENER_SYNC);
		if (this->type == IDENT_SENDER) kill(this->notifypid, WOLPER_CHLD_SENDER_SYNC);
	}

}

void wolperdrone::listen(void)
{
	/* wait for connection from master */
	this->client_sock = listen_ipc_socket(this->prime_sock);
}

/*
 * returns the first usable adress of *device
 */
uint32_t wolperdrone::get_device_addr(void)
{

    /*
     * returns the first usable adress of *device
     * by using the kernel ioctl instead of libdnet
     */

    struct intf_entry if_e;
    intf_t *if_h;
    char ip[MAX_IP_STR_LEN + 1];
	int32_t ip_addr = 0;
	
    int fd;
    struct ifreq ifr;
    
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        MSG(MSG_DBG, "Failed to open socket: %\n", strerror(errno));
        goto failsafe;
    }

    // I want to get an IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
    
    // I want IP address attached to this->iface
    snprintf(ifr.ifr_name, INTF_NAME_LEN - 1, "%s", this->iface);
    
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        MSG(MSG_DBG, "Failed to ioctl: %\n", strerror(errno));
        close(fd);
        goto failsafe;
    }

    if (close(fd) == -1) {
        MSG(MSG_DBG, "Failed to close: %\n", strerror(errno));
        // and ignore, I mean, who cares
    }

    snprintf(ip, MAX_IP_STR_LEN, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    ip_addr = inet_addr(ip);
    
    if (ip_addr != 0 && ip_addr != -1) {
        MSG(MSG_DBG, "IP %s found (method ioctl + kernel)\n", ip);
        return ip_addr;
    }

failsafe:
    /*
     * returns the first usable adress of *device
     * by using the intf_ methods from libdnet -- fallback
     */
    // TODO: remove this way once the warning below is not triggered anywhere
	
    if_h = intf_open();
	if (!if_h) {
		MSG(MSG_DBG, "Could not open interface config\n");
		return 0;
	}

	bzero(ip, MAX_IP_STR_LEN);

    MSG(MSG_DBG, "INTF_NAME_LEN is %i\n", INTF_NAME_LEN);

    snprintf(if_e.intf_name, INTF_NAME_LEN - 1, "%s", this->iface);
    if_e.intf_len = sizeof(struct intf_entry);

	if (intf_get(if_h, &if_e) == -1) {
		MSG(MSG_DBG, "intf_get failed\n");
		return 0;
	}

    MSG(MSG_DBG, "addr_ntoa(&if_e.intf_addr) = %s\n", addr_ntoa(&if_e.intf_addr));
    snprintf(ip, MAX_IP_STR_LEN, "%s", addr_ntoa(&if_e.intf_addr));
	strtok(ip,"/");

	ip_addr = inet_addr(ip);

	if (ip_addr == -1 || ip_addr == 0) {
    	return 0;
	} else {
        MSG(MSG_DBG, "IP %s found (method intf_ + libdnet)\n", ip);
        MSG(MSG_WARN, "ioctl method to find IP failed, sucessfully used libdnet instead\n");
		return ip_addr;
    }
}


uint32_t wolperdrone::get_workunit(char *msg)
{	
	struct ipc_message *ipc_m;
    struct ipc_sendunit *ipc_s;
    struct ipc_listenunit *ipc_l;
    struct targets *t;
    struct ports *p;

	struct target_info ti_tmp;
	
	char *msg_ptr;
    uint32_t i, x;
	uint32_t correct_packet_len = 0;

	msg_ptr = msg;

	ipc_m = (struct ipc_message *) msg_ptr;
	msg_ptr += sizeof(struct ipc_message);
	
	if (this->type == IDENT_SENDER) {
		ipc_s = (struct ipc_sendunit *) msg_ptr;
		msg_ptr += sizeof(struct ipc_sendunit);

		MSG(MSG_DBG, "[recv ipc workunit] ipc_s->ip_data_len = %d, ipc_s->port_data_len = %d\n", ipc_s->ip_data_len, ipc_s->port_data_len);
		correct_packet_len = sizeof(struct ipc_message) + sizeof(struct ipc_sendunit) + (ipc_s->ip_data_len * sizeof(struct targets)) + (ipc_s->port_data_len * sizeof(struct ports));

		if (ipc_m->msg_len != correct_packet_len) {
			MSG(MSG_WARN, "[ipc workunit] msg_len: %d real: %d\n", ipc_m->msg_len, correct_packet_len);
			return 0;
		}
		
		this->pps = ipc_s->pps;
		this->sport = ipc_s->sport;
		this->listener_addr = ipc_s->listener_addr;
		this->secret = ipc_s->secret;
		this->tcpops = ipc_s->tcpops;
		this->retry = ipc_s->retry;
		
		/* Targets */
		for (i=0; i < ipc_s->ip_data_len; i++) {
			t = (struct targets *)msg_ptr;
			MSG(MSG_TRC, "[workload] hosts [%d]: %d <-> %d\n", i, t->ipaddr, t->range);	
		
			/* Create targetlist */
			for (x = 0; x < t->range; x++) {
				ti_tmp.addr = htonl(ntohl(t->ipaddr) + x);
				this->targets.push_back(ti_tmp);
			}
		
			msg_ptr += sizeof(struct targets);
		}
		
		/* Port Definitionen  */
		for (i=0; i < ipc_s->port_data_len; i++) {
			p = (struct ports *)msg_ptr;
			MSG(MSG_TRC, "[workload] ports [%d]: %d <-> %d\n", i, p->port, p->port + p->range);
			
			/* Create portlist */
			for (x = p->port; x <= (p->port + p->range); x++) {
				this->ports.push_back(x);
			}
			
			msg_ptr += sizeof(struct ports);
		}
	}

	// randomize port index for each host
	for (i=0; i < this->targets.size(); i++) {
		this->targets[i].port_index = get_rnd_uint32() % (this->ports.size());
	}
	
	if (this->type == IDENT_LISTENER) {
		ipc_l = (struct ipc_listenunit *) msg_ptr;
		msg_ptr += sizeof(struct ipc_listenunit);

		correct_packet_len = sizeof(struct ipc_message) + sizeof(struct ipc_listenunit);

		if (ipc_m->msg_len != correct_packet_len) {
			MSG(MSG_WARN, "[ipc workunit] msg_len: %d real: %d\n", ipc_m->msg_len, correct_packet_len);
			return 0;
		}

		this->sport = ipc_l->sport;
		this->timeout = ipc_l->timeout;
		this->secret = ipc_l->secret;
	}
	
	return correct_packet_len;
}

void wolperdrone::ipc_loop()
{
	uint32_t msg_len = 0;
	
	struct ipc_message *ipc_m;

	char *msg = NULL;	
	
	/* ipc communication starts here */
	while (1) {
		msg_len = get_ipc_message(this->client_sock, &msg);
		if (msg_len > 0) { /* valid message */
			
			ipc_m = (struct ipc_message *) msg;
			
			switch (ipc_m->msg_type) {
				case MSG_HELO: /* challenge response authentication */
                    if (this->drone_state != STATE_WAIT_FOR_WORK) {
                        MSG(MSG_DBG, "ignoring HELO request: worng drone state\n");
                        continue;
                    }
					MSG(MSG_DBG, "[ipc in] HELO\n");
                    ipc_send_challenge(this->client_sock, this->myaddr, this->drone_id);
                    this->drone_state = STATE_CHALLENGE_SENT;
					break; // case
                case MSG_AUTH:
                    if (this->drone_state != STATE_CHALLENGE_SENT) {
                        MSG(MSG_DBG, "ignoring AUTH request: worng drone state\n");
                        continue;
                    }
					MSG(MSG_DBG, "[ipc in] AUTH\n");
					
					if (check_auth(msg, this->username, this->password)) {
                        ipc_send_ready(this->client_sock);
                        this->drone_state = STATE_AUTHENTICATED;
                    } else {
                        ipc_send_error(this->client_sock, "authentication failed");
                        this->drone_state = STATE_WAIT_FOR_WORK;
                        close_ipc_socket(this->client_sock);
						this->client_sock = 0;
						this->client_sock = listen_ipc_socket(this->prime_sock);
                    }
					break; // case
				case MSG_IDENT: /* Please identify yourself */
					if (this->drone_state != STATE_AUTHENTICATED) {
						MSG(MSG_DBG, "ignoring IDENT request: worng drone state\n");
						continue;
					}
					MSG(MSG_DBG, "[ipc in] IDENT\n");

					if (this->type == IDENT_LISTENER) ipc_send_listener_ident(this->client_sock, this->listener_addr);
					if (this->type == IDENT_SENDER) ipc_send_sender_ident(this->client_sock);
					    
					this->drone_state = STATE_IDENT_SENT;
					break; // case
				case MSG_WORKUNIT: /* Something to do */
					if (drone_state != STATE_IDENT_SENT) {
						MSG(MSG_DBG, "ignoring workunit request: worng drone state\n");
						continue;
					}

					/* get workunit */
					if (this->get_workunit (msg)) {
						ipc_send_ready(this->client_sock);
						drone_state = STATE_READY_TO_GO;
					} else {
						ipc_send_error(this->client_sock, "Invalid workunit received");
						drone_state = STATE_WAIT_FOR_WORK;
					}
					break; // case
				case MSG_START: /* Voran! */
					if (this->drone_state != STATE_READY_TO_GO) {
						MSG(MSG_DBG, "ignoring start request: worng drone state\n");
						continue;
					}
					
					/* Start Send loop */
					MSG(MSG_DBG, "[ipc in] START\n");
					ipc_send_busy(this->client_sock);
					this->drone_state = STATE_BUSY;
					
					if (this->type == IDENT_SENDER) this->send_packets();
					if (this->type == IDENT_LISTENER) this->packet_loop(this->pcap);
						
					ipc_send_workdone(this->client_sock);
				
					if(this->single) {						
						sleep(1);
						this->cleanup();
						exit(0);
					}
					MSG(MSG_USR, "[info] finished scan. ready for the next one.\n");
					drone_state = STATE_WAIT_FOR_WORK;
					this->ports.clear();
					this->targets.clear();	
					sleep(1); /* Warten das die Nachricht auch wirklich gesendet wurde */
					/* Wieder neu auf einen Client warten */
					close_ipc_socket(this->client_sock);
					this->client_sock = 0;
					this->client_sock = listen_ipc_socket(this->prime_sock);
					break; // case
				case MSG_ERROR:
					// print_error(msg, NULL); FIXME
					break; // case
				case MSG_QUIT:
					if (this->single) {
						MSG(MSG_USR, "[info] MSG_QUIT from master. exiting.\n");
						sleep(1);
						this->cleanup();
						exit (0);
					}
					//stop_packets();
					MSG(MSG_USR, "[info] stopping packets...\n");
					ipc_send_workdone(this->client_sock);
					drone_state = STATE_WAIT_FOR_WORK;					
					/* Wieder neu auf einen Client warten */
					close_ipc_socket(this->client_sock);
					this->client_sock = 0;
					this->client_sock = listen_ipc_socket(this->prime_sock);
					break; // case
				default:
					MSG(MSG_WARN, "invalid Message Type: ignoring\n");
					break; // case
			}
            
            free(msg); msg = NULL; ipc_m = NULL;
		} else { /* Oh mein Gott! Es kommt direkt auf uns zu!! */
			if (this->single) {
				MSG(MSG_WARN, "error while reading from master. Exiting.\n");
				sleep(1);
				this->cleanup();
				exit(1);
			}
			MSG(MSG_DBG, "error while reading from master. Resetting connections.\n");
			drone_state = STATE_WAIT_FOR_WORK; /* Drone State Reset */
			this->ports.clear();
			this->targets.clear();
			/* Wieder neu auf einen Client warten */
			close_ipc_socket(this->client_sock);
			this->client_sock = 0;
			this->client_sock = listen_ipc_socket(this->prime_sock);
		}
	}

	return;
}

/*
 * randomize portlist... 
 */
void wolperdrone::randomize_portlist(void) 
{
	MSG(MSG_DBG, "randomizing portlist...\n");
	
	uint16_t rnd, i;
	uint16_t temp;

	if (this->ports.size() > 3)  {
		for (i = 0 ; i < this->ports.size() ; i++) {
			rnd = get_rnd_uint16() % (i+1);
			temp = this->ports[i];
			this->ports[i] = this->ports[rnd];
			this->ports[rnd] = temp;
		}
	}
	
	return;
}

/*
 * randomize hostlist... 
 */
void wolperdrone::randomize_hostlist(void) 
{
	MSG(MSG_DBG, "randomizing hostlist...\n");
	
	uint32_t rnd, i;
	struct target_info temp;

	if (this->targets.size() > 3)  {
		for (i = 0 ; i < this->targets.size() ; i++) {
			rnd = get_rnd_uint32() % (i+1);
			temp = this->targets[i];
			this->targets[i] = this->targets[rnd];
			this->targets[rnd] = temp;
		}
	}
	
	return;
}


/*
 * try to resolve arp entries for each host in the local network
 * and use it for further pakets
 * TODO: this solution does not work, since manual arp requests are not added to the arp table
 */
void wolperdrone::arpscan(void)
{
    struct in_addr addr, gwaddr;
	struct arp_entry arpent;
    struct route_entry rtent;
    int j, usec;
    bool localaddr = true;

    MSG(MSG_DBG, "ARP resolving all local hosts...\n");

    arp_t *arp_handler = arp_open();
    route_t	*route_handler = route_open();

    for (vector<struct target_info>::iterator i = this->targets.begin(); i != this->targets.end(); ) {
        addr.s_addr = i->addr;
        uint32_t srcip = 0;
        eth_addr_t *srcmac;

        if ((srcip = getsrcip(i->addr)) == 0) {
		    MSG(MSG_WARN, "Cannot reach host %s. Skipping it.\n", inet_ntoa(addr));
            this->targets.erase(i);
            continue; // do not increment i, it already points to next value after erasing
        }

        if ((srcmac = gethwaddr(this->iface)) == NULL) {
            MSG(MSG_WARN, "Cannot get source MAC for host %s. Skipping it.\n", inet_ntoa(addr));
            this->targets.erase(i);
            continue; // do not increment i, it already points to next value after erasing
        }

        arpent.arp_pa.addr_type = ADDR_TYPE_IP;
	    arpent.arp_pa.addr_bits = IP_ADDR_BITS;
	    arpent.arp_pa.addr_ip = i->addr;
        memcpy(&rtent.route_dst, &arpent.arp_pa, sizeof(rtent.route_dst));

        if (route_get(route_handler, &rtent) == 0 &&
		        rtent.route_gw.addr_ip != i->addr) {

            gwaddr.s_addr = rtent.route_gw.addr_ip;
		    memcpy(&arpent.arp_pa, &rtent.route_gw, sizeof(arpent.arp_pa));
            localaddr = false;
       	}

        for (j = 0, usec = 10; ; j++, usec *= 100) {
		    if (arp_get(arp_handler, &arpent) == 0)
			    break;
		    
            if (j == 3)
                break;

            send_arp_request(this->iface, i->addr, srcip, srcmac);
            
            usleep(usec);
	    }

        free(srcmac); srcmac = NULL;

        if (j == 3) { // 3 arp requests went unanswered
            if (localaddr) {
                MSG(MSG_WARN, "Cannot get ARP reply for local host %s. Skipping it.\n", inet_ntoa(addr));
            } else {
                MSG(MSG_WARN, "Cannot get ARP reply for gateway %s used to route host %s. Skipping this host.\n", inet_ntoa(gwaddr), inet_ntoa(addr));
            }
            
            this->targets.erase(i);
            continue; // do not increment i, it already points to next value after erasing
        }

        if (localaddr) {
            MSG(MSG_WARN, "Resolved ARP entry %s for host %s.\n", mtoa(&arpent.arp_ha.addr_eth), inet_ntoa(addr));
        } else {
            MSG(MSG_WARN, "Resolved ARP entry %s for gateway %s used to route host %s.\n", mtoa(&arpent.arp_ha.addr_eth), inet_ntoa(gwaddr), inet_ntoa(addr));
        }
        
        // TODO: store it

        ++i;
	}

    arp_handler = arp_close(arp_handler);
    route_handler = route_close(route_handler);

}



/* 
 * send packet loop
 */
void wolperdrone::send_packets(void) 
{
	struct in_addr addr;
	struct in_addr saddr;
	struct pollfd pfd;
	struct ipc_message *ipc_m;
	
	uint32_t msg_len = 0;
	uint32_t i;
	uint32_t trynum = 0;

	uint16_t port = 0;
	uint16_t port_index = 0;
	
	uint8_t *tcpops = NULL;
    uint8_t tcpopslen = 0;

	// BETA TESTING:
	struct ipc_sender_stats stats;
	stats.packets_total = this->ports.size() * this->targets.size() * this->retry;
	stats.packets_send = 0;
	stats.packets_send_time = tv2long(NULL);
	bool send_stats = false;
	
	uint32_t last = 0;
	uint32_t prozent = 0;

    bool use_ualarm = true;
	
	char *msg;	

	/* is the ualarm timer available? */
	if (!ualarm_init_tslot(this->pps)) {
        use_ualarm = false;
        MSG(MSG_WARN, "no ualarm timer available. falling back to gettimeofday() method.\n");
        sleep_init_tslot(this->pps);
	}
    MSG(MSG_DBG, "initialized timer slot\n");

	this->randomize_portlist();
	this->randomize_hostlist();

    //this->arpscan(); // does not work like this
	
	saddr.s_addr = this->listener_addr;

	/* should we send statistic messages? */
	if ((((this->ports.size() * this->targets.size()) * this->retry) / this->pps) > 30) {
		/* only send statistic messages for scans that take longer than 30 seconds */
		send_stats = true;
	}
	
	/* use tcp options for syn scan? */
	if (this->tcpops) {
		MSG(MSG_DBG, "using tcp options for scan\n");
		tcpops = (uint8_t *) "\003\003\012\001\002\004\005\264\010\012\377\377\377\377\000\000\000\000\004\002";
		tcpopslen = 20;
	}
	
	if (!this->single) {
		MSG(MSG_USR, "[info] drone started: sending packets...\n");
	}

    // open libdnet ARP table lookup and Route table lookup handlers
    arp_t *arp_handler = arp_open();
    route_t	*route_handler = route_open();

	for (trynum = 0; trynum < this->retry; trynum++) {
		for (i=0; i < this->ports.size(); i++) {
			for (vector<struct target_info>::iterator x = this->targets.begin(); x != this->targets.end(); ) {
				if (use_ualarm)
                    ualarm_start_tslot();
                else
					sleep_start_tslot();
				
				addr.s_addr = x->addr;

				// printf("i = %d index = %d size = %d ---> ", i, x->port_index, this->ports.size());				
				port_index = (i + x->port_index) >= this->ports.size() ? (i + x->port_index) - this->ports.size() : (i + x->port_index);
				port = this->ports[port_index];

				//fprintf(stderr,"[--->] %s:%d [%d]\n",inet_ntoa(addr), port, port_index);

				if (send_tcp_packet(this->ip_handle, addr, port, saddr, this->sport, TH_SYN, 0, 0, 0, tcpops, tcpopslen) < 0) {
                    MSG(MSG_WARN, "Error while sending package.\n");
                }

                // For the first port of this system, lets find out if
                //   a) the system is in the local subnet or reached via gateway (route table)
                //   b) if we got an ARP entry (most likely due to the kernel sending ARP requests in send_tcp_packet)
                //
                // If there is not ARP entry for a local system, or no ARP entry of the gateway for a routed system, we will warn
                // the user and drop the target from our target list!
                if (i == 0) { // first port for this system
                    struct in_addr addr, gwaddr;
                	struct arp_entry arpent;
                    struct route_entry rtent;
                    bool localaddr = true;

                    addr.s_addr = x->addr;

                    arpent.arp_pa.addr_type = ADDR_TYPE_IP;
	                arpent.arp_pa.addr_bits = IP_ADDR_BITS;
	                arpent.arp_pa.addr_ip = x->addr;
                    memcpy(&rtent.route_dst, &arpent.arp_pa, sizeof(rtent.route_dst));

                    // test whether the target is non-local
                    if (route_get(route_handler, &rtent) == 0 &&
		                    rtent.route_gw.addr_ip != x->addr) {

                        gwaddr.s_addr = rtent.route_gw.addr_ip;
		                memcpy(&arpent.arp_pa, &rtent.route_gw, sizeof(arpent.arp_pa));
                        localaddr = false;
                   	} else {
                        localaddr = true;
                    }

                    // see if there is an ARP entry for the target (or its gateway if non-local)
                    if (arp_get(arp_handler, &arpent) == 0) {
                        // TODO: store arp entry eventually
                        ++x; // next target
                    } else {
                        if (localaddr) {
                            MSG(MSG_WARN, "Cannot get ARP reply for local host %s. Skipping it.\n", inet_ntoa(addr));
                        } else {
                            MSG(MSG_WARN, "Cannot get ARP reply for gateway %s used to route host %s. Skipping this host.\n", inet_ntoa(gwaddr), inet_ntoa(addr));
                        }

                        this->targets.erase(x); // if no ARP, drop the target :'-|
                        // do not increment i, it already points to next value after erasing
                    }
                } else {
                    ++x; // next target
                }

				stats.packets_send++;

				// BETA TESTING				
				if (send_stats) {
					prozent = ((float)stats.packets_send / stats.packets_total) * 100;			
					if (prozent % 5 == 0) {
						if (prozent > last) {
							stats.packets_current_time = tv2long(NULL);
							ipc_send_sender_stats(this->client_sock, &stats);
							last = prozent;
						}
					}
				}
					
				MSG(MSG_TRC, "send: %s:%d\n", inet_ntoa(addr), this->ports[i]);
				
				/* Wait for events on pcap fd */
				pfd.fd=this->client_sock;
				pfd.events=POLLIN|POLLPRI;
				pfd.revents=0;			
				
				while (poll(&pfd, 1, 0) < 0) {
                    if (errno == EINTR || errno == EAGAIN) continue;
					MSG(MSG_WARN, "poll fails: %s", strerror(errno));
                    break;
				}
			
				/* incoming ipc message */
				if (pfd.revents & POLLIN) {
					msg_len = get_ipc_message(this->client_sock, &msg);
					if (msg_len > 0) {
						ipc_m = (struct ipc_message *) msg;
						if (ipc_m->msg_type == MSG_QUIT) {
							MSG(MSG_USR, "[info] received QUIT from master: breaking packet loop.\n");
							return;
						} else if (ipc_m->msg_type == MSG_WORKUNIT) {
							MSG(MSG_DBG, "additional workunit received. adding to existing one\n");
							if (get_workunit (msg)) {
								ipc_send_ready(this->client_sock);
							} else {
								ipc_send_error(this->client_sock, "invalid workunit received");
							}				
						} else {
							MSG(MSG_WARN, "received invalid message from master. ignoring.\n");
						}

                        free(msg); msg = NULL; ipc_m = NULL;
					} else { /* Oh mein Gott! Es kommt direkt auf uns zu!! */
						MSG(MSG_WARN, "error while reading from Master. Resetting connections.\n");
						return;
					}
				
				}

				/* wait to end of time slot and handle slowlyness... */
				if (use_ualarm) {
					uint64_t ualarm_iterations = ualarm_getiterations();
					if (ualarm_iterations > 0) {
						MSG(MSG_DBG, "needed too much time for this send slot: "
								"%lld iterations have passed while scanning %s:%u \n", 
								ualarm_iterations, inet_ntoa(addr), port);
					}
					ualarm_end_tslot();
                } else {
					sleep_end_tslot();
                }
			}
		}
		if (!this->single) { MSG(MSG_USR, "[info] round %d/%d finished\n", trynum+1, this->retry); }
	}

    // close arp and route table lookup handlers
    arp_handler = arp_close(arp_handler);
    route_handler = route_close(route_handler);
	
	return;
}

/*
 * create custom tcp packet 
 */
int16_t wolperdrone::send_tcp_packet(
	ip_t *s, /* Socket */
    struct in_addr dst_addr, /* Target Address */
    uint16_t dst_port, /* Target Port */
	struct in_addr src_addr, /* Source Address */
	uint16_t src_port, /* Source Port */
	uint16_t tcp_flags, /* TCP Flags */
	uint32_t seq, /* TCP Sequence */
	uint16_t ack, /* ACK Number */
	uint16_t window, /* Window */
	uint8_t *options, /* TCP Options */
	uint32_t optlen) /* Option Lenght */
{
	int16_t bytes;
	uint32_t syncookie;
	uint32_t packet_len;
	
	packet_len = sizeof(struct ip) + sizeof(struct tcphdr) + optlen;
	unsigned char *packet = (unsigned char *) safe_zalloc(packet_len);
	
	struct ip *ip = (struct ip *) packet;
	struct pseudo_header *pseudo =  (struct pseudo_header *) (packet + sizeof(struct ip) - sizeof(struct pseudo_header));
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
	
	//to.sin_addr.s_addr = dst_addr.s_addr;
	//to.sin_family = AF_INET;
	//to.sin_port = htons(dst_port);

	bzero((unsigned int *) packet, sizeof(struct ip) + sizeof(struct tcphdr));

	/* Pseudo header for the TCP checksum */
	pseudo->s_addr = src_addr;
	pseudo->d_addr = dst_addr;
	pseudo->protocol = IPPROTO_TCP;
	pseudo->length = htons(sizeof(struct tcphdr) + optlen);
	
	tcp->th_sport = htons(src_port);
	tcp->th_dport = htons(dst_port);
	
	/* Magic ! */
	TCPHASHTRACK(syncookie, dst_addr.s_addr, dst_port, src_port, this->secret);
	tcp->th_seq = htonl(syncookie);

	/* ACK Number */
	if (ack)
		tcp->th_ack = htonl(ack);
	else if (tcp_flags & TH_ACK)
		tcp->th_ack = get_rnd_uint16();

	/* Window */
	if (window)
		tcp->th_win = htons(window);
	else
		tcp->th_win = get_rnd_uint16();

	tcp->th_off = 5 + (optlen /4);
	tcp->th_flags = tcp_flags;

	/* Copy TCP options to the packet ( if any ) */
	if (optlen)
		memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr), options, optlen);
            
	/* TCP Checksum */
	tcp->th_sum = in_cksum((uint16_t *)pseudo, sizeof(struct tcphdr) + optlen + sizeof(struct pseudo_header));
  
	bzero(packet, sizeof(struct ip)); 
	
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_len = ntohs(sizeof(struct ip) + sizeof(struct tcphdr) + optlen);

	ip->ip_id = get_rnd_uint16();
	ip->ip_ttl = (get_rnd_uint() % 23) + 37;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src.s_addr = src_addr.s_addr;
	ip->ip_dst.s_addr = dst_addr.s_addr;

	ip->ip_sum = in_cksum((uint16_t *)ip, sizeof(struct ip));
	
	bytes = ip_send(s, packet, packet_len);

	if (bytes < 0) {
		// we hope, that the errno is still set after a failed sendto call inside
		if (errno == EINTR) { // interrupted system call
			MSG(MSG_DBG, "Interrupted, retrying ip_send\n");			
			while (bytes < 0 && errno == EINTR) {
				bytes = ip_send(s, packet, packet_len);
			}
		} else { // other error, that we cannot fix here
			MSG(MSG_DBG, "Error from ip_send: %s\n", strerror(errno));
		}
	}

	free(packet);
	
	return bytes;
}

/*
 * PCAP Initialisieren:
 * Device öffnen, Filter erstellen, kompilieren und installieren
 * Zum Schluss wird das ganze auf nonblocking gesetzt
 */
pcap_t *wolperdrone::init_pcap(char *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];	// Hier werden die PCAP Fehlermeldungen gespeichert
	char filter_exp[512]; /* Pcap Filter Str */
	pcap_t *handle;			// Der Packethandler
	struct bpf_program fp;		// Der kompilierte Filter
	bpf_u_int32 mask;			// Netzmaske unseres Devices
	bpf_u_int32 net;			// IP Unseres Devices
	struct in_addr src_addr;	/* SRC Addr des Listeners */
	int datalink;
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "[warn] can't get netmask for device %s\n", dev);
	}

	handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
	if (handle == NULL) {
		MSG(MSG_ERR, "couldn't open device %s: %s\n", dev, errbuf);
		return 0;
	}
	
	src_addr.s_addr = this->listener_addr;
	// sprintf(filter_exp, "dst host %s && (icmp or (tcp && (dst port %d)))", inet_ntoa(src_addr), this->sport);
	sprintf(filter_exp, "dst host %s && (icmp or tcp)", inet_ntoa(src_addr));
	MSG(MSG_DBG, "[pcap] pcap_filter (device: %s): %s\n", dev, filter_exp);

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		MSG(MSG_ERR, "couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 0;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		MSG(MSG_ERR, "couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 0;
	}

	if (pcap_setdirection(handle, PCAP_D_IN) == -1) {
		MSG(MSG_WARN, "couldn't set pcap direction: %s", pcap_geterr(handle));
	}

	if (pcap_setnonblock(handle, 1, errbuf) == -1) {
		MSG(MSG_ERR, "could not set nonblocking option on pcap handler: %s\n", errbuf);
		return 0;
	}

	
	/* Get datalink-type to calculate header offset */
	if ((datalink = pcap_datalink(handle)) < 0) {
		MSG(MSG_ERR, "cannot obtain datalink information: %s", pcap_geterr(handle));
	}	

	/* to be continued */
	switch(datalink) {
		case DLT_EN10MB: this->datalink_offset = 14; break;
		case DLT_IEEE802: this->datalink_offset = 22; break;
		case DLT_LINUX_SLL: this->datalink_offset = 16; break;
	}

	return handle;
}

void help(char *me)
{
	printf("usage : %s -i <interface> -p <port> [-S|-L]\n\n", me);
	printf("-i <ifname>            : interface used for sending/listening \n");
	printf("-p [<ip>:]<port>       : port to listen for master\n");
	printf("-L|-S                  : create a [S]ender or [L]istener drone\n");
	printf("-D                     : run as daemon in background\n");
	printf("-d                     : increased the debug intensity\n");
	printf("-s                     : single mode (do not use this if in doubt)\n");
	printf("--notify-pid <pid>     : PID to signal after setup (single mode only)\n");
	printf("-h, --help             : show this help\n");
	printf("--keyfile <filename>   : read user:password of the drone from the file\n");
	printf("--pidfile <filename>   : write deamon pid to the file on start (-D needed)\n");
	exit (0);
}

/*
 * receive packet loop
 */
uint32_t wolperdrone::packet_loop(pcap_t *handle) 
{
	uint32_t pcap_fd=0; /* PCAP Filedescriptor */
	uint32_t msg_len=0;
	struct pollfd pfd[2];
	
	struct ipc_message *ipc_m;
	char *msg;
	
	uint64_t timeout_ns=0;
	
	pcap_fd=pcap_get_selectable_fd(handle);

	if (pcap_fd < 0) {
		fatal("cant get selectable fd from pcap device, exiting");
	}

	if (!this->single) { MSG(MSG_USR, "[info] drone started: starting packet loop...\n"); }
	
	while(1) {		
		
		if (timeout_ns) {
			//fprintf(stderr, "c-time: %llu\n", tv2long (NULL));
			if (tv2long (NULL) >= timeout_ns) {
				MSG(MSG_DBG, "listener timeout\n");
				return 0;
			}
		}
		
		/* Wait for events on pcap fd */
        pfd[0].fd=pcap_fd;
        pfd[0].events=POLLIN|POLLPRI;
        pfd[0].revents=0;
			
		/* Wait for ipc messages from master */
		pfd[1].fd=this->client_sock;
		pfd[1].events=POLLIN|POLLPRI;	
		pfd[1].revents=0;		

        if (poll(pfd, 2, 50) < 0) {
            MSG(MSG_WARN, "poll fails: %s", strerror(errno));
        }

		/* Packet received */
		if (pfd[0].revents & POLLIN) {
            pcap_dispatch(handle, 1, handle_packet, NULL);
        }
		
		/* incoming ipc message */
		if (pfd[1].revents & POLLIN) {
			msg_len = get_ipc_message(this->client_sock, &msg);
			if (msg_len > 0) {
				ipc_m = (struct ipc_message *) msg;
				if (ipc_m->msg_type == MSG_QUIT) {
					if (!this->single) {
						MSG(MSG_USR, "[info] received QUIT from master, breaking packet loop in %d seconds.\n", this->timeout); 
					}
					//fprintf(stderr, "[mnt debug] timestamp QUIT: %ld\n", time(NULL));
					timeout_ns = tv2long (NULL) + (this->timeout * 1000000);
					//fprintf(stderr, "s-time: %llu\n", timeout_ns);
				} else {
					MSG(MSG_WARN, "received invalid message from master. ignoring.\n");
				}
                
                free(msg); msg = NULL; ipc_m = NULL;
			} else { /* Oh mein Gott! Es kommt direkt auf uns zu!! */
				MSG(MSG_WARN, "error while reading from Master. Resetting connections.\n");
				return 0;
			}
		}
	}
}

/*
 * extreme ugly wrapper function 
 */
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	drone.parse_packet(args, header, packet);
}

/*
 * PCAP Hook. Wird durch pcap_dispatch ein Paket gelesen wird es an diese Funktion übergeben
 */
void wolperdrone::parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct ip *ip;
    const struct tcphdr *tcp;
	
	int size_ip;
    int size_tcp;
	
	uint32_t syncookie;
	
    char buff_src[64];
    char buff_dst[64];

    ip = (struct ip*)(packet + this->datalink_offset);
    size_ip = ip->ip_hl*4;
	
	if (size_ip < 20) {
        MSG(MSG_WARN, "invalid IP header length: %u bytes\n", size_ip);
        return;
    }
	
	if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct tcphdr*)(packet + this->datalink_offset + size_ip);
        size_tcp = tcp->th_off*4;
        
		if (size_tcp < 20) {
            MSG(MSG_WARN, "invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }

		strncpy(buff_src, inet_ntoa(ip->ip_src), sizeof(buff_src));
		strncpy(buff_dst, inet_ntoa(ip->ip_dst), sizeof(buff_dst));
		MSG(MSG_TRC, "RECV [tcp] %s:%d -> %s:%d [%s] ttl=%d id=%d iplen=%d seq=%d win=%d\n", buff_src, ntohs(tcp->th_sport),buff_dst, ntohs(tcp->th_dport), getflags(tcp->th_flags), ip->ip_ttl, ip->ip_id, htons(ip->ip_len), tcp->th_seq, tcp->th_win);

		/* Check TCP Hash Tracking */
		TCPHASHTRACK(syncookie, ip->ip_src.s_addr, ntohs(tcp->th_sport), ntohs(tcp->th_dport), this->secret);
		if (syncookie == (ntohl(tcp->th_ack) - 1)) {		
		    if ((tcp->th_flags & (TH_SYN|TH_ACK))==(TH_SYN|TH_ACK)) {
				ipc_send_portstate(this->client_sock, ntohs(tcp->th_sport), ip->ip_src.s_addr);
				//MSG(MSG_DBG, "open: %d\n",ntohs(tcp->th_sport));
		    } else if ((tcp->th_flags & (TH_ACK|TH_RST))==(TH_ACK|TH_RST)) {
				//MSG(MSG_DBG, "closed: %d\n",ntohs(tcp->th_sport));
		    }
		} else {
			MSG(MSG_TRC, "TCPHASHTRACK: not my packet\n");
		}
    }

	return;
}

void wolperdrone::cleanup(void) {
	if (this->client_sock) {
		/* send error message to master */
		ipc_send_error(this->client_sock, "SIGINT received");
	
		/* wait for message to send */
		sleep(1);
	}
	
	/* close client socket */
	if (this->client_sock) close_ipc_socket(this->client_sock);
	this->client_sock = 0;

	/* close prime socket */
	if (this->prime_sock) close_ipc_socket(this->prime_sock);
	this->prime_sock = 0;
}

