#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdarg.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <unistd.h>

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "shared.h"
#include "ipc.h"
#include "drone.h"
#include "main.h"
#include "net.h"

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

std::string exec(char* cmd) {
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "ERROR";
    char buffer[128];
    std::string result = "";
    while(!feof(pipe)) {
    	if(fgets(buffer, 128, pipe) != NULL)
    		result += buffer;
    }
    pclose(pipe);
    return result;
}

void hwaddrtest() {
	char *iface = (char*) "eth0";
    eth_addr_t *srcmac = gethwaddr(iface);

    std::string mymac = exec((char*) "ip link show dev eth0 | grep link | awk '{print $2}' | tr -d '\\n'");

    if (strncmp(mymac.c_str(), mtoa(srcmac), 18) != 0) {
        printf("ip link returned: %s\n", mymac.c_str());
        printf("gethwaddr returned: %s\n", mtoa(srcmac));
        FAILM("Our MAC was detected incorrectly.");
    }
}


void srciptest() {
    uint32_t dstip = inet_addr("127.0.0.1");
    uint32_t srcip = getsrcip(dstip);

    if (strncmp((char*) "127.0.0.1", ntoa(srcip), 16) != 0) {
        printf("getsrcip returned: %s\n", ntoa(srcip));
        FAILM("Our localhost IP should be 127.0.0.1");
    }

    dstip = inet_addr("37.202.2.212");
    srcip = getsrcip(dstip);

    std::string myip = exec((char*) "ip addr show dev eth0 | grep 'inet ' | awk '{print $2}' | cut -d '/' -f 1 | tr -d '\\n'");

    if (srcip == 0 || strncmp(myip.c_str(), ntoa(srcip), 18) != 0) {
        printf("ip addr returned: %s\n", myip.c_str());
        printf("getsrcip returned: %s\n", ntoa(srcip));
        FAILM("Our IP was detected incorrectly.");
    }
}

// TODO: more tests for send_arp_request if ever needed, needs root
void arpreqtest1() {
    if (getuid() != 0) {
        printf("You need to be root for this test. Skipping it.\n");
        return;
    }

    char *iface = (char*) "eth0";
    uint32_t dstip = inet_addr("10.201.1.1");

    uint32_t srcip = getsrcip(dstip);
    //printf("Source IP : %s\n", ntoa(srcip));

    eth_addr_t *mac = gethwaddr(iface);
    //printf("Source MAC: %s\n", mtoa(mac));
    
    send_arp_request(iface, dstip, srcip, mac);

    free(mac); mac = NULL;    
}


void runSuite(){
	cute::suite s;

	//increase_debuglevel();
	//increase_debuglevel();

	//TODO add your test here
	s.push_back(CUTE(hwaddrtest));
	s.push_back(CUTE(srciptest));
    s.push_back(CUTE(arpreqtest1));
    
	cute::ide_listener<> lis;
	cute::makeRunner(lis)(s, "nettest");
}

int main(){
    runSuite();
    return 0;
}
