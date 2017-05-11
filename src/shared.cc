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
#include <sys/stat.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>
#include <pwd.h>

/* hpet stuff */
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <linux/hpet.h>
#include <sys/ioctl.h>

#include <fcntl.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H
#include <netinet/tcp.h>
#define NETINET_TCP_H
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/evp.h>
#include <syslog.h>

#include "shared.h"

static uint64_t sleep_delay=0;
static uint64_t sleep_s_time=0;

static uint64_t hpet_iterations=0;

extern struct global_informations global;

/*
Für ganz pöhse (tm) Fehler
*/
void fatal(const char *format, ...) {
	char buff[1024];
	va_list args;
	va_start(args, format);
	memset(buff, 0, sizeof(buff));
	vsnprintf( buff, sizeof(buff) - 1, format, args);
	fprintf(stderr, "[fatal] %s\n", buff);
	va_end(args);
	exit(1);
}

/*
Gibt das aktuelle Datum als String zurück
*/
char *get_time_str(void) 
{
	time_t 	timep;
	char	*mytime;

	mytime = (char *)safe_zalloc(128*sizeof(char));

	timep=time(NULL);
	strncpy(mytime,(char *)ctime(&timep),strlen(ctime(&timep))-1);

	return mytime;
}

/*
 Stream Socket erstellen
*/
int create_stream_socket(int proto) 
{
	int s;

	if((s=socket(AF_INET, SOCK_STREAM, proto))== -1) {
		MSG(MSG_ERR, "tcp socket call failed: %s\n", strerror(errno));
		exit(-1);
	}
	
	return s;
}

/*
 * create unix domain socket
 */
int create_domain_socket(int proto)
{
	int s;

	if((s=socket(PF_UNIX, SOCK_STREAM, proto))== -1) {
		MSG(MSG_ERR, "unix domain socket call failed: %s\n", strerror(errno));
		exit(-1);
	}
	
	return s;
}
/*
Socket in nonblocking Modus setzen
*/
int unblock_socket(int s) {
	int options;
	options = O_NONBLOCK | fcntl(s, F_GETFL);
	fcntl(s, F_SETFL, options);
	return 1;
} 

/*
Raw Socket erstellen für das angegebene Protokoll
*/
int create_raw_socket(int proto) 
{
	int s, on = 1;

	if ((s = socket(AF_INET, SOCK_RAW, proto)) == -1) {
		perror("socket");
		return 1;
	}

	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
		perror("setsockopt");
		return 2;
	}

	return s;
}

/*
Socket in blocking mode setzen
*/
int block_socket(int s) {
	int options;
	options = (~O_NONBLOCK) & fcntl(s, F_GETFL);
	fcntl(s, F_SETFL, options);
	return 1;
}

/* 
 IP oder Hostnamen in 32 Bit Network-Byte-Order umwandeln
*/
uint32_t host2long(const char *host) {
	struct in_addr addr;
	struct hostent *he;
	
	if(is_ip(host)) { /* IP-Adresse */
		if(!(inet_aton(host, &addr))) {
			return 0;
		} else {
			return addr.s_addr;
		}	
	} else { /* Hostname */
		if((he = gethostbyname(host))==NULL) {
			return 0;
		} else {
			bcopy(he->h_addr, &addr, he->h_length);
			return addr.s_addr;
		}
	}
}

/*
 * is it a single ip address?
 */
bool is_ip(const char *host)
{
    uint8_t numbers = 0;
    uint8_t dots = 0;

	const char *p = host;
	
	while(*p != '\0')
    {
		if(*p=='.') dots++;
        else if(isdigit(*p)) numbers++;
        else return false;
		p++;
    }

    return (numbers >= 4) && (numbers <= 12) && (dots == 3);
} 

/*
 * is it a cidr notated ip adress?
 */
bool is_ip_cidr(char *host)
{
    uint8_t numbers = 0;
    uint8_t dots = 0;
	uint8_t slash = 0;

	char *p = host;
	
	while(*p != '\0')
    {
        if((*p)=='.') dots++;
		else if((*p)=='/') slash++;
		else if(isdigit(*p)) numbers++;
        else return false;
		p++;
    }

    return (numbers >= 4) && (numbers <= 15) && (dots == 3) && (slash==1);
} 

/*
 * is it a ip range?
 */
bool is_ip_range(char *host)
{
    uint8_t numbers = 0;
    uint8_t dots = 0;
	uint8_t separator = 0;
	uint8_t range = 0;
	
	char *p = host;
	
	while(*p != '\0')
    {
        if((*p)=='.') dots++;
        else if(isdigit(*p)) numbers++;
		else if ((*p) == ',') separator++;
		else if ((*p) == '-') range++;
        else return false;
		p++;
    }

    return (dots == 3) && ((range > 0) || (separator > 0));
} 

/*
Erzeugt eine zufällige Zahl vom Typ unsigned int
*/
unsigned int get_rnd_uint(void) 
{
	return rand(); 
}

/*
Erzeugt eine zufällige Zahl vom Typ unsigned short int
*/
uint16_t get_rnd_uint16(void)
{
	return rand(); 
}

/*
Erzeugt eine zufällige Zahl vom Typ unsigned long int
*/
uint32_t get_rnd_uint32(void)
{
	return rand(); 
}

/*
Sichere allokation von Speicher
*/
void *safe_zalloc(int size) 
{
	void *mymem;
	if (size < 0) {
		fprintf(stderr, "[err] tried to malloc negative amount of memory!!!\n");
		exit(0);
	}
	
	mymem = calloc(1, size);
	
	if (mymem == NULL) {
		fprintf(stderr, "[err] malloc Failed! Probably out of space.\n");
		exit(0);
	}
	
	return mymem;
}

/********* HPET timer (deprecated, not in use) ***************/

static void hpet_event(int val) {
	hpet_iterations++;
}

void hpet_start_tslot(void) {
	hpet_iterations=0;
}

void hpet_end_tslot(void) {
	while (hpet_iterations == 0) {
		(void) pause();
	}
}

uint32_t init_hpet_handle(void) {
	uint32_t fd, value;
	
	// open hpet device
	fd = open("/dev/hpet", O_RDONLY);
    if (fd < 0) 
		return 0;

	if ((fcntl(fd, F_SETOWN, getpid()) == 1) || ((value = fcntl(fd, F_GETFL)) == 1) || (fcntl(fd, F_SETFL, value | O_ASYNC) == 1)) 
		return 0;

	return fd;
}

uint32_t hpet_init_tslot(uint32_t pps, uint32_t fd) {
    struct sigaction old_handler, new_handler;
    struct hpet_info info;
	uint32_t r;

    sigemptyset(&new_handler.sa_mask);
    new_handler.sa_flags = SA_RESTART; // restart syscalls after interrupt
    new_handler.sa_handler = hpet_event;

    sigaction(SIGIO, NULL, &old_handler);
    sigaction(SIGIO, &new_handler, NULL);

	if (!fd) {
		return 0;
	}

	// set frequency
    if (ioctl(fd, HPET_IRQFREQ, pps) < 0) {
        //printf("  TODO ERROR ON HPET_IRQFREQ: %s\n", strerror(errno));
		MSG(MSG_DBG, "HPET_IRQFREQ: %s\n", strerror(errno));
        return 0;
	}

	// get hpet info
    if (ioctl(fd, HPET_INFO, &info) < 0) {
        //printf("  TODO ERROR ON HPET_INFO: %s\n", strerror(errno));
        MSG(MSG_DBG, "HPET_INFO: %s\n", strerror(errno));
		return 0;
	}

	// HPET EPI
	r = ioctl(fd, HPET_EPI, 0);
    if (info.hi_flags && (r < 0)) {
        //printf("  TODO ERROR ON HPET_EPI: %s\n", strerror(errno));
        MSG(MSG_DBG, "HPET_EPI: %s\n", strerror(errno));
		return 0;
	}

	// Start HPET Timer
    if (ioctl(fd, HPET_IE_ON, 0) < 0) {
        //printf("  TODO ERROR ON HPET_IE_ON: %s\n", strerror(errno));
        MSG(MSG_DBG, "HPET_IE_ON: %s\n", strerror(errno));
		return 0;
	}


	hpet_iterations=0;

	return 1;
}

/********* ualarm() based timer implementation (default) *******/

static volatile uint64_t ualarm_iterations=0;

static void ualarm_event(int val) {
	ualarm_iterations++;
}

uint64_t ualarm_getiterations() {
	return ualarm_iterations;
}

void ualarm_start_tslot(void) {
	ualarm_iterations=0;
}

void ualarm_end_tslot(void) {
    while (ualarm_iterations == 0) {
	    pause();
	}
}

int ualarm_init_tslot(uint32_t pps) {
    struct sigaction old_handler, new_handler;

    sigemptyset(&new_handler.sa_mask);
    new_handler.sa_flags = SA_RESTART; // restart syscalls after interrupt
    new_handler.sa_handler = ualarm_event;

    sigaction(SIGALRM, NULL, &old_handler);
    sigaction(SIGALRM, &new_handler, NULL);

    uint64_t second = 1000000; /* microseconds */
    uint64_t ualarm_delay=(second / pps); /* divide */

    // glibc/kernel only allows ualarm value of < 1000000
    if (ualarm_delay >= second) {
        ualarm_delay = second - 1;
    }

    ualarm_iterations=0;

    while (ualarm(ualarm_delay, ualarm_delay) < 0) {
        if (errno == EINTR) continue;
        MSG(MSG_DBG, "ualarm: %s\n", strerror(errno));
        return 0;
    }

    return 1;
}


/********* poll loop timer implementation (fallback) *******/

static uint64_t get_tod(void) {
    struct timeval tv;
    uint64_t tt=0;

    gettimeofday(&tv, NULL);

    tt=tv.tv_sec;
    /* some 64 bit platforms have massive tv_usecs, truncate them */
    tt=tt << (4 * 8);
    tt += (uint32_t)(tv.tv_usec & 0xffffffff);

    return tt;
}

void sleep_start_tslot(void) {
	sleep_s_time=get_tod();
	return;
}

void sleep_end_tslot(void) {
    while (1) {
        if ((get_tod() - sleep_s_time) >= sleep_delay) {
            break;
        }
    }
    sleep_s_time=0;	
}

void sleep_init_tslot(uint32_t pps) {
    uint64_t second = 1000000; /* microseconds */
		
    sleep_delay=(second / pps);	/* muhahaha */
}

/*
Erzeugt einen String mit den entsprechende gesetzten TCP Flags
*/
const char *getflags(uint8_t flags) 
{
	char buffer[10];

	bzero(buffer, sizeof(buffer));

	if (flags == 0)      strcat(buffer, "");
	if (flags & TH_RST)  strcat(buffer, "R");
	if (flags & TH_SYN)  strcat(buffer, "S");
	if (flags & TH_ACK)  strcat(buffer, "A");
	if (flags & TH_PUSH) strcat(buffer, "P");
	if (flags & TH_FIN)  strcat(buffer, "F");
	if (flags & TH_URG)  strcat(buffer, "U");

	return(strdup(buffer));
}

char *md5(char *plaintext, uint16_t len) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	char *hash, *p;
	unsigned int md_len, i;

	md = EVP_get_digestbyname("md5");

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, plaintext, (size_t) len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);

	hash = (char *) safe_zalloc(MD5_ASCII_SIZE);
    	bzero(hash, MD5_ASCII_SIZE);
	
	for(i = 0, p = hash; i < md_len; i++, p += 2)
		sprintf(p, "%02x", md_value[i]);
	
	return hash;
}

char *sha512(char *plaintext, uint16_t len) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	char *hash, *p;
	unsigned int md_len, i;

	OpenSSL_add_all_digests();

	md = EVP_get_digestbyname("sha512");

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, plaintext, len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);

	hash = (char *)safe_zalloc(SHA512_ASCII_SIZE);

	for(i = 0, p = hash; i < md_len; i++, p += 2)
		sprintf(p, "%02x", md_value[i]);

	return hash;
}

char *generate_digest(char *text, uint32_t text_len, char *key, uint32_t key_len)
{
	EVP_MD_CTX *context, *tctx;
	unsigned char k_ipad[65];
	unsigned char k_opad[65];
	unsigned char tk[16];
	unsigned char *digest;
	unsigned int md_len, i;
	char *hash, *p;
	
	digest = (unsigned char *) safe_zalloc(16);
	
	if (key_len > 64) {        
        tctx = EVP_MD_CTX_create();
		EVP_DigestInit(tctx, EVP_md5());
		EVP_DigestUpdate(tctx, key, key_len);
		EVP_DigestFinal_ex(tctx, tk, &md_len);
        EVP_MD_CTX_destroy(tctx);
		
		key = (char *) tk;
		key_len = 16;
	}
	
	bzero( k_ipad, sizeof k_ipad);
	bzero( k_opad, sizeof k_opad);
	bcopy( key, k_ipad, key_len);
	bcopy( key, k_opad, key_len);

	for (i=0; i<64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	
    context = EVP_MD_CTX_create();
	EVP_DigestInit(context, EVP_md5());
	EVP_DigestUpdate(context, k_ipad, 64);
	EVP_DigestUpdate(context, text, text_len);
	EVP_DigestFinal_ex(context, digest, &md_len);
    EVP_MD_CTX_destroy(context);
	
    context = EVP_MD_CTX_create();
	EVP_DigestInit(context, EVP_md5());
	EVP_DigestUpdate(context, k_opad, 64);
	EVP_DigestUpdate(context, digest, 16);
	EVP_DigestFinal_ex(context, digest, &md_len);
    EVP_MD_CTX_destroy(context);
	
	hash = (char *) safe_zalloc(MD5_ASCII_SIZE);
	
	for(i = 0, p = hash; i < md_len; i++, p += 2)
		sprintf(p, "%02x", digest[i]);	
	
    free(digest);

	return hash;
}

char *get_scan_duration(mytime_t start, mytime_t stop) {
	mytime_t hours, minutes, seconds; //, milliseconds;			// time variables
	mytime_t time_delta_sec; //, time_delta_msec;
	
    //printf("start time: %u\n", start);
	//tt_start += start->millitm;
	
    //printf("stop time: %u\n", stop);
	//tt_stop += stop->millitm;	
	
	char *duration = (char *) safe_zalloc(512);						// duration string
	
	/* difference in milliseconds */
	//time_delta_msec = tt_stop - tt_start;
	
	/* difference in seconds */
	time_delta_sec = stop - start;
    //printf("delta: %u\n", time_delta_sec);
	
	hours = time_delta_sec / 3600LLU;
	minutes = (time_delta_sec - (hours * 3600LLU)) / 60LLU;
	seconds = time_delta_sec - (hours * 3600LLU) - (minutes * 60LLU);
	//milliseconds = (time_delta_msec - ((hours * 3600) * 1000) - ((minutes * 60) * 1000) - (seconds * 1000));
	
	if (hours > 0) 
		sprintf(duration, "%juh%jum%jus\n", hours, minutes, seconds);	
	else if (minutes > 0)
		sprintf(duration, "%jum%jus\n", minutes, seconds);	
	else 
		sprintf(duration, "%ju seconds\n", seconds);
		
	return duration;
}

uint8_t file_copy(char *src, char *dst)
{
  FILE *from, *to;
  char ch;

  /* open source file */
  if((from = fopen(src, "rb"))==NULL) {
    MSG(MSG_ERR, "cannot open file '%s': %s\n", src, strerror(errno));
  }

  /* open destination file */
  if((to = fopen(dst, "wb"))==NULL) {
    MSG(MSG_ERR, "cannot open file '%s': %s\n", dst, strerror(errno));
  }

  /* copy the file */
  while(!feof(from)) {
    ch = fgetc(from);
    if(ferror(from)) {
      MSG(MSG_ERR, "error reading file '%s'\n", src);
    }
    if(!feof(from)) fputc(ch, to);
    if(ferror(to)) {
      MSG(MSG_ERR, "error writing file '%s'\n", dst);
    }
  }

  if(fclose(from)==EOF) {
    MSG(MSG_ERR, "error closing file '%s': %s\n", src, strerror(errno));
  }

  if(fclose(to)==EOF) {
    MSG(MSG_ERR, "error closing file '%s': %s\n", dst, strerror(errno));
  }

  return 0;
}

/*
 * returns timeval in microseconds
 */
unsigned long int tv2long(struct timeval *tv) 
{
	struct timeval tvtmp;
	
	if (tv) {
		return ( (tv->tv_sec * 1000000 ) + tv->tv_usec );
	} else {
		gettimeofday(&tvtmp, 0);
		return (uint32_t)((tvtmp.tv_sec * 1000000 ) + tvtmp.tv_usec );
	}
}


/*
 * calculate ip checksum
 */
uint16_t in_cksum(uint16_t *ptr, uint32_t nbytes) {
	register uint32_t sum;
	uint16_t oddbyte;
	register uint16_t answer;

	sum = 0;
	while (nbytes > 1)  {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *) &oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}

	sum  = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}

/* output */
#ifndef NOMAINFUNCTION
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
			exit(1);
			break;

		case MSG_DBG:
		case MSG_TRC:
			fprintf(stderr, "[Debug   %s:%d] %s", file, lineno, buf);
			break;

		case MSG_VBS:
		case MSG_USR:
			printf("%s", buf);
			
	}

	/* syslog output */
	if (global.syslog) {
		switch (type) {
			case MSG_VBS:
			case MSG_USR:
				syslog(LOG_INFO, "%s", buf);
				break;

			case MSG_WARN:
				syslog(LOG_WARNING, "%s", buf);
				break;

			case MSG_ERR:
				syslog(LOG_ERR, "%s", buf);
				break;
		}
	}
	

	return;
}
#endif

int drop_priv(void)
{
	uid_t ruid, euid, suid;

	// get uid of nobody
	struct passwd *nobody_pwd;
	nobody_pwd = getpwnam("nobody");

	if (setresuid(nobody_pwd->pw_uid, nobody_pwd->pw_uid, nobody_pwd->pw_uid) < 0)
		return 0;

	if (getresuid(&ruid, &euid, &suid) < 0) 
		return 0;

	if (ruid != nobody_pwd->pw_uid || euid != nobody_pwd->pw_uid || suid != nobody_pwd->pw_uid) 
		return 0;
	
	return 1;
}

void gotoxy(int x, int y) {
	/* store cursor position */
	printf("\033[s");

	/* set cursor position */
	printf("\033[%dd\033[%dG", y, x);
	
	return;
}

void reset_cursor(void) {
	/* restore cursor position */
	printf("\033[u");

	return;
}

void cls(void) {
	/* clear screen */
	printf("\033[2J");

	return;
}



void get_userpass_from_file(FILE *fd, char *username, char *password)
{
	char *current = username;

	uint32_t index = 0;
	int32_t ch;
	
	while((ch = getc(fd)) != EOF) {
		if (ch == ':' || ch == '\r' || ch == '\n' || ch == '\t' || ch == '\0') {
			if (index == 0) continue;
			current[index] = '\0';
			if (current == password) break;
			current = password;
			index = 0;
		} else if (index < MAX_USERNAME_LEN -1 && index < MAX_PASSWORD_LEN -1) {
			current[index++] = (char) ch;
		} else {
			MSG(MSG_ERR, "One of the specifications from your input file is too long (> %d chars)\n", (int) sizeof(current));
		}
	}
	
	if (index > 0) {
		current[index] = '\0';
	}
	
	return;
}
