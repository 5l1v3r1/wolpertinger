#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shared.h"
#include "ipc.h"
#include "drone.h"
#include "main.h"

extern struct global_informations global;

bool error = false;

void _display(int type, const char *file, int lineno, const char *fmt, ...) 
{
	char buf[MAX_OUTPUT_LEN];
	va_list ap;
	va_start(ap, fmt);
	vsprintf (buf, fmt, ap);
	
	switch (type) {
		case MSG_WARN:
			fprintf(stderr, "[Warning %s:%d] %s", file, lineno, buf);
			break;			
			
		case MSG_ERR:
			fprintf(stderr, "[Error   %s:%d] %s", file, lineno, buf);
			error = true;
			break;

		case MSG_DBG:
		case MSG_TRC:
			fprintf(stderr, "[Debug   %s:%d] %s", file, lineno, buf);
			break;

		case MSG_VBS:
		case MSG_USR:
			//printf("%s", buf);
			break;
			
	}
}


bool _hascachedsudopassword() {
    bool success = false;

	pid_t sudotest;
	char *newargv[20];
	uint8_t argc = 0;
	char *newenviron[] = { NULL };
    int status;
	
    /* execute sudo -v -n to check whether the password has been cached */
	newargv[argc++] = strdup("sudo");
	newargv[argc++] = strdup("-v");
	newargv[argc++] = strdup("-n");
	newargv[argc] = NULL;

	sudotest = fork();
	if (sudotest < 0) {
		printf("Could not fork: %s\n", strerror(errno));
        FAILM("Could not fork sudo.\n");
		return 1;
	} else if (sudotest == 0) {
		if (execvpe("sudo", newargv, newenviron) < 0) {
			printf("Could not execute %s: %s\n", "sudo", strerror(errno));
            FAILM("Could not execute sudo.\n");
		}
	} else { // parent process
		waitpid(sudotest, &status, 0);
		if (WEXITSTATUS(status) == 0) {
			 success = true; // password cached and no failure
		}
	}

    /* free newargv */
    for (int i=0; i < argc && i < 20; ++i) {
        free(newargv[i]);
    }

    return success;
}


uint8_t _metaipctest_send_child_sync = 0; /* sender process synchronized */
uint8_t _metaipctest_recv_child_sync = 0; /* listener process synchronized */

/* get children sync signals */
void _metaipctest_s_child_sync(int arg) {
	_metaipctest_send_child_sync = 1;
}

void _metaipctest_r_child_sync(int arg) {
	_metaipctest_recv_child_sync = 1;
}


inline void _rundistribution(drone_list &dl) {
	uint32_t chld_timeout = 0;

	error = false;

	/* signal handler for children in single mode */
	signal(WOLPER_CHLD_SENDER_SYNC, _metaipctest_s_child_sync);	
	signal(WOLPER_CHLD_LISTENER_SYNC, _metaipctest_r_child_sync);

	/* add local mode drones */
	dl.set_local();
	dl.add_drone(IDENT_LISTENER, 0, DEFAULT_PASS); /* add listener drone */
	dl.add_drone(IDENT_SENDER, 0, DEFAULT_PASS); /* add sender_drone */

	//dl.iface = strdup("eth0");

	/* fork sender/listener drone */
	if (!fork_drones(dl.get_device())) {
		FAILM("Could not fork drones.\n");
	} else {

		/* wait for children to sync */
		chld_timeout = tv2long(NULL) + CHLD_SYNC_TIMEOUT;
		while (_metaipctest_send_child_sync  < 1 || _metaipctest_recv_child_sync < 1) {
			if (tv2long(NULL) > chld_timeout) {
				FAILM("timeout while waiting for childs to SYNC with master\n");
			}
		}

		// let the drones setup the unix domain sockets
		sleep(1);
	}

	/* connect to all drones and start challenge response authentication */
	if (!dl.connect_and_authenticate()) {
		FAILM("Can not connect to or authenticate with at least one sender and one listener drone\n");
	}

	ASSERTM("Error in the preparation process", !error);

    //printf("prepared drone@%p : mypass@%p\n", dl.dl[0], dl.dl[0].my_pass);
    //printf("prepared drone@%p : mypass@%p\n", dl.dl[1], dl.dl[1].my_pass);

	/* sending relevant IPC workload message! */
	dl.distribute_workunits();

    //printf("distributed drone@%p : mypass@%p\n", dl.dl[0], dl.dl[0].my_pass);
    //printf("distributed drone@%p : mypass@%p\n", dl.dl[1], dl.dl[1].my_pass);

	ASSERTM("Error in the workunit distribution process", !error);

	// stop drones
    //printf("Calling dl.quit_all_drones()\n");
	dl.quit_all_drones();
}


void smallworkload() {
    if (getuid() != 0 && !_hascachedsudopassword()) {
        printf("You need to be root for this test or have an active sudo session. Skipping it.\n");
        return;
    }

	drone_list dl;
	unsigned long res;

    res = dl.add_portstr((char*) "80,443");
    ASSERT_EQUALM("Number of added ports is wrong", 2, res);

   	res = dl.add_hostexp((char*) "127.0.0.1");
    ASSERT_EQUALM("Number of IPs is wrong", 1, res);

	_rundistribution(dl);
}

void largeworkload() {
    if (getuid() != 0 && !_hascachedsudopassword()) {
        printf("You need to be root for this test or have an active sudo session. Skipping it.\n");
        return;
    }

	drone_list dl;

	unsigned long res;
    char portstr[65535*6];
    char *p = portstr + snprintf(portstr, 7, "1");

    for (unsigned long i=1; i<=65535; ++i) {
        p += snprintf(p, 7, ",%lu", i);
	}

    res = dl.add_portstr(portstr);
    ASSERT_EQUALM("Number of added ports is wrong", 65536, res);

	for (unsigned long i=0; i<14000; ++i) {
        unsigned long z = (unsigned int) inet_addr("10.0.0.0") + htonl(i);
    	res = dl.add_hostexp((char*) inet_ntoa(*(struct in_addr *)&z));
        ASSERT_EQUALM("Buffer-Overflow: Number of IPs is suddently wrong", (i+1), res);
	}

	_rundistribution(dl);
}


void runSuite(){
	cute::suite s;

	//increase_debuglevel();
	//increase_debuglevel();

	//TODO add your test here
	s.push_back(CUTE(smallworkload));
	s.push_back(CUTE(largeworkload));
    
	cute::ide_listener<> lis;
	cute::makeRunner(lis)(s, "metaipc");
}

int main(){
    //global.verbose = true;
    //global.debug = true;

    runSuite();
    return 0;
}
