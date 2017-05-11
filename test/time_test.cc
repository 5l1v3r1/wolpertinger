#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"

#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>

#include "shared.h"

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

void gettimeofday_benchmark()
{
	int i;
	struct timespec tv_start, tv_end;
    struct timeval tv_tmp;
    int count = 1 * 1000 * 1000 * 50;
    clockid_t clockid;
    
    int rv = clock_getcpuclockid(0, &clockid);

    if (rv) {
            perror("clock_getcpuclockid");
            return;
    }

    clock_gettime(clockid, &tv_start);
    for(i = 0; i < count; i++)
            gettimeofday(&tv_tmp, NULL);
    clock_gettime(clockid, &tv_end);

    long long diff = (long long)(tv_end.tv_sec - tv_start.tv_sec)*(1*1000*1000*1000);
    diff += (tv_end.tv_nsec - tv_start.tv_nsec);

    printf("[**] gettimeofday precision: %f ns/cycle\n", (double)diff / (double)count);
}


void wolpertinger_hpet_run(uint32_t pps) {
    uint32_t hpetfd = 0;
    uint32_t i, t;
    struct timeval t1, t2;
    
    if (getuid() != 0) {
        printf("  wolpertinger hpet: You need to be root for this test. Skipping it.\n");
        return;
    }

    if (pps > 50000) {
        printf("  wolpertinger hpet: pps to high for hpet, skipping this run\n");
        return;
    }

    //if (hpetfd == 0) {
    if ((hpetfd = init_hpet_handle()) == 0) {
        printf("  wolpertinger hpet: FAILED to initialize hpet handle\n");
        return;
    }
    //}
    if (hpet_init_tslot(pps, hpetfd) == 0) {
        printf("  wolpertinger hpet: FAILED to init tslot\n");
        return;
    }

    gettimeofday(&t1, NULL);
    for(i = 0; i < pps; i++) {
        hpet_start_tslot();
        hpet_end_tslot();
    }
    gettimeofday(&t2, NULL);
	
    t = ((t2.tv_sec * 1000000) + t2.tv_usec) - ((t1.tv_sec * 1000000) + t1.tv_usec);
    printf("  wolpertinger hpet: %u μs / 1000000 μs run (%.2f %%)\n", t, (double) t / 1000000.0 * 100.0);

    if (close(hpetfd) < 0) {
        printf("  wolpertinger hpet: FAILED to close hpet: %s\n", strerror(errno));
        return;
    }
}

void wolpertinger_ualarm_run(uint32_t pps) {
    uint32_t i, t;
    struct timeval t1, t2;
    
    if (ualarm_init_tslot(pps) == 0) {
        printf("  wolpertinger ualarm: FAILED to init tslot\n");
        return;
    }

    gettimeofday(&t1, NULL);
    for(i = 0; i < pps; i++) {
        ualarm_start_tslot();
        ualarm_end_tslot();
    }
    gettimeofday(&t2, NULL);
	
    t = ((t2.tv_sec * 1000000) + t2.tv_usec) - ((t1.tv_sec * 1000000) + t1.tv_usec);
    printf("  wolpertinger ualarm: %u μs / 1000000 μs run (%.2f %%)\n", t, (double) t / 1000000.0 * 100.0);
}

void wolpertinger_sleep_run(uint32_t pps) {
    uint32_t i, t;
    struct timeval t1, t2;
    
    sleep_init_tslot(pps);

    gettimeofday(&t1, NULL);
    for(i = 0; i < pps; i++) {
        sleep_start_tslot();
        sleep_end_tslot();
    }
    gettimeofday(&t2, NULL);
	
    t = ((t2.tv_sec * 1000000) + t2.tv_usec) - ((t1.tv_sec * 1000000) + t1.tv_usec);
    printf("  wolpertinger sleep: %u μs / 1000000 μs run (%.2f %%)\n", t, (double) t / 1000000.0 * 100.0);
}

void general_usleep_run(uint32_t pps) {
    uint32_t i, t;
    struct timeval t1, t2;

    long microseconds = (double) (1000 * 1000) / (double) pps;

    gettimeofday(&t1, NULL);
    for(i = 0; i < pps; i++)
        usleep(microseconds);
    gettimeofday(&t2, NULL);

    t = ((t2.tv_sec * 1000000) + t2.tv_usec) - ((t1.tv_sec * 1000000) + t1.tv_usec);
    printf("  general usleep: %u μs / 1000000 μs run (%.2f %%)\n", t, (double) t / 1000000.0 * 100.0);
}

void general_nanosleep_run(uint32_t pps) {
    uint32_t i, t;
    struct timeval t1, t2;
    struct timespec wait;

    long microseconds = (double) (1000 * 1000) / (double) pps;
    wait.tv_sec = microseconds / (1000 * 1000);
    wait.tv_nsec = (microseconds % (1000 * 1000)) * 1000;

    gettimeofday(&t1, NULL);
    for(i = 0; i < pps; i++)
        nanosleep(&wait, NULL);
    gettimeofday(&t2, NULL);

    t = ((t2.tv_sec * 1000000) + t2.tv_usec) - ((t1.tv_sec * 1000000) + t1.tv_usec);
    printf("  general nanosleep: %u μs / 1000000 μs run (%.2f %%)\n", t, (double) t / 1000000.0 * 100.0);
}


void smallppstest() {
    // 1 pps corner case
    wolpertinger_ualarm_run(1);
    wolpertinger_sleep_run(1);
}


void smalltimeruntest() {
    long microseconds;
    unsigned int j;

    int pps[] = {1, 500, 2000, 5000, 100000};

    for (j = 0; j < sizeof(pps) / sizeof(pps[0]); ++j) {
        microseconds = (double) (1000 * 1000) / (double) pps[j];

        printf("[%02d] %d pps == %ld μs timers\n", (j+1), pps[j], microseconds);

        wolpertinger_ualarm_run(pps[j]);
        wolpertinger_sleep_run(pps[j]);
    }

    gettimeofday_benchmark();
}

void fulltimeruntest() {
    long microseconds;
    unsigned int j;

    int pps[] = {1, 100, 500, 1000, 2000, 5000, 10000, 50000, 100000, 200000, 500000};

    for (j = 0; j < sizeof(pps) / sizeof(pps[0]); ++j) {
        microseconds = (double) (1000 * 1000) / (double) pps[j];

        printf("[%02d] %d pps == %ld μs timers\n", (j+1), pps[j], microseconds);

        // general test
        general_usleep_run(pps[j]);
        general_nanosleep_run(pps[j]);

        //wolpertinger test runs
        wolpertinger_hpet_run(pps[j]);
        wolpertinger_ualarm_run(pps[j]);
        wolpertinger_sleep_run(pps[j]);
    }

    gettimeofday_benchmark();
}


void runSuite(){
	cute::suite s;

	//increase_debuglevel();
	//increase_debuglevel();

	//TODO add your test here
    s.push_back(CUTE(smallppstest));
    s.push_back(CUTE(smalltimeruntest));
    //s.push_back(CUTE(fulltimeruntest));
    
	cute::ide_listener<> lis;
	cute::makeRunner(lis)(s, "timetest");
}

int main(){
    runSuite();
    return 0;
}
