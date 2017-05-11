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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/timeb.h>

#include "shared.h"
#include "ipc.h"
#include "drone.h"
#include "database.h"

extern struct global_informations global;


static sqlite3 *db;											// SQLite Datenbank
static uint32_t scan_id;									// Portscan ID
static char default_port_string[MAX_DEFAULT_PORTSTR_LEN];	// default port string
static char *pport_string = default_port_string;			// pointer to default_port_string
static char **credentials;									// drone credentials
static char db_version[MAX_STRING_LEN];						// version string of the db schema


// callback for retreiving an integer
static int get_int_cb(void *param, int argc, char **argv, char **azColName){	
	int *i = (int *)param;					// create integer pointer
	
	if (argc > 0)							// if there is a value
		*i = atoi(argv[0]);					// save it as integer
		
	return 0;
}


// callback for retreiving a string
static int get_string_cb(void *param, int argc, char **argv, char **azColName){		
	if (argc > 0)											// if there is a value
		strncpy((char *)param, argv[0], MAX_STRING_LEN);	// copy it as string
		
	return 0;
}

// callback for retreiving drone credentials
static int get_drone_credentials_cb(void *param, int argc, char **argv, char **azColName){
	if (argc != 2) {
		credentials = NULL;
		return 0;
	}

	/* allocate memory */
	credentials = (char **) safe_zalloc(sizeof(char *) * 2);
	credentials[0] = (char *) safe_zalloc(MAX_USERNAME_LEN);
	credentials[1] = (char *) safe_zalloc(MAX_PASSWORD_LEN);

	/* get username and password */
	snprintf(credentials[0], MAX_USERNAME_LEN, "%s", argv[0]);
	snprintf(credentials[1], MAX_PASSWORD_LEN, "%s", argv[1]);
	
	return 0;
}

// callback for retreiving the default port list
static int get_portlist_cb(void *param, int argc, char **argv, char **azColName){
	uint32_t len = 0;
	char buffer[MAX_STRING_LEN];
	
	for (int i = 0; i < argc; i++) {		
		snprintf(buffer, MAX_STRING_LEN, "%s,", argv[i]);
		len = strlen(buffer);

		if ((pport_string + len) < buffer + MAX_DEFAULT_PORTSTR_LEN)
			strcpy(pport_string, buffer);
		
		pport_string += len;
	}
		
	return 0;
}


// callback for creating a scan report
static int create_report_cb(void *param, int argc, char **argv, char **azColName){
	uint32_t port = 0;
	char *service = NULL;
	struct in_addr addr;
			
	for (int i = 0; i < argc; i++) {		
		service = NULL;
		if (strcmp(azColName[i], "ip") == 0) {
			addr.s_addr = strtoul(argv[i], NULL, 10);			
		} else if (strcmp(azColName[i], "port") == 0) {
			port = atoi(argv[i]);
		} else if (strcmp(azColName[i], "name") == 0) {
			service = strdup(argv[i]);
		}		
	}	

	if (service) {
		printf("OPEN %-16s%6d/tcp [%s]\n", inet_ntoa(addr), port, service);		
		free(service);
	} else {
		printf("OPEN %-16s%6d/tcp\n", inet_ntoa(addr), port);				
	}	
	
	return 0;
}


/* open database */
int db_open(void) {
	int rc, path_len;
	char *path;
	char *homepath;
	char *homepathdir;

	/* get home dir database location */
	path_len = strlen(getenv("HOME")) + strlen(DATABASE_HOME) + strlen(DATABASE) + 3;
	homepath = (char *) safe_zalloc (path_len);
	snprintf(homepath, path_len, "%s%s%s", getenv("HOME"), DATABASE_HOME, DATABASE);
	
	/* check if database exists in home dir (~/.wolpertinger/wolpertinger.db) */
    if (FILE * file = fopen(homepath, "r")) {
		/* file exists, open database */
		fclose(file);
    } else {
		/* file doesn't exist. copy it from PKGDATADIR */
		printf("wolpertinger.db does not exist. creating a new one in homedir.\n");

		/* try to create wolpertinger directory */
		path_len = strlen(getenv("HOME")) + strlen(DATABASE_HOME) + 3;
		homepathdir = (char *) safe_zalloc (path_len);
		snprintf(homepathdir, path_len, "%s%s", getenv("HOME"), DATABASE_HOME);
		if ((mkdir(homepathdir, 0700) < 0) && (errno != EEXIST)) {
			MSG(MSG_WARN, "mkdir failed: %s\n", strerror(errno));
		}
		free(homepathdir);
        
		/* copy file from PKGDATADIR */
		path_len = strlen(PACKAGE_DATA_DIR) + strlen(DATABASE) + 3;
		path = (char *)safe_zalloc(path_len);
		snprintf(path, path_len, "%s/%s", PACKAGE_DATA_DIR, DATABASE);
		file_copy(path, homepath);
		free(path);
		
		if (chmod(homepath, 0700) < 0) {
			MSG(MSG_WARN, "chmod failed: %s\n", strerror(errno));
		}
	}

	/* open database in homedir */
	rc = sqlite3_open(homepath, &db);
	if (rc) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	
	free(homepath);

	/* check database schema version */
	db_find_version();
    //MSG(MSG_WARN, "database schema version: %s\n", db_version);
	
	return 0;
}

int db_find_version(void) {
	char *zErrMsg = NULL;
	int rc;	
	
	rc = sqlite3_exec(db, "SELECT value FROM options WHERE key='db_version';", &get_string_cb, db_version, &zErrMsg);
	if (rc != SQLITE_OK) {
		//MSG(MSG_WARN, "expected SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		snprintf(db_version, MAX_STRING_LEN, "0.7+");
	}

    if ((strncmp(db_version, "0.7+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.3+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.5+", MAX_STRING_LEN) == 0)) {
		MSG(MSG_WARN, "Your wolpertinger database structure is deprecated.\n  You should use wolper-mcp.py --update-db to update the structure of your current database\n  or wolper-mcp.py --reset-db to delete your database and use a new one instead.\n");
    } else if (strncmp(db_version, "0.8.7+", MAX_STRING_LEN) == 0) {
        //MSG(MSG_WARN, "This is the latest database structure version.\n");
	} else {
		MSG(MSG_ERR, "Unknown database version. You may use wolper-mcp.py --reset-db to delete your database and use a new one instead.\n");
    }
	
	return rc;
}


/* write database */
int db_write(char *sql_stmt) {
	int rc;
	char *zErrMsg = 0;
	
	MSG(MSG_DBG, "SQL write statement: %s\n", sql_stmt);
	
	rc = sqlite3_exec(db, sql_stmt, 0, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		// print SQL error message
		MSG(MSG_WARN, "SQL error: %s\n  Statement skipped: %s\n", zErrMsg, sql_stmt);
		sqlite3_free(zErrMsg);
	}
	
	return rc;
}


/* read database */
int db_read(char *sql_stmt, void *var, int (*callback)(void*, int, char**, char**)) {
	int rc;
	char *zErrMsg = 0;

	MSG(MSG_DBG, "SQL read statement: %s\n", sql_stmt);
			
	rc = sqlite3_exec(db, sql_stmt, callback, var, &zErrMsg);
	if (rc != SQLITE_OK) {
		MSG(MSG_WARN, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	
	return rc;
}


/* close database */
int db_close(void) {
	int rc;
	sqlite3_stmt * stmt;
	
	MSG(MSG_DBG, "SQL close database\n");

	// finish all remaining statements
	while ((stmt = sqlite3_next_stmt(db, NULL)) != NULL) {
		sqlite3_finalize(stmt);
	}
	
	rc = sqlite3_close(db);
	if (rc != SQLITE_OK) {
		MSG(MSG_WARN, "SQL error while closing database: %i\n", rc);
	}
	
	return rc;
}


/* create scan */
int db_create_scan(mytime_t starttime, mytime_t estendtime, struct info *scan_info) {
	char sql_stmt[MAX_STMT_LEN];
	
	// insert new scan
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "insert into scan (tag, pps, hosts, ports, source_ip, source_port, start_time, end_time) values (%Q, %u, %u, %u, %u, %u, %llu, %llu)", scan_info->scan_tag, scan_info->pps, scan_info->num_hosts, scan_info->num_ports, scan_info->source_ip, scan_info->source_port, starttime, estendtime);
	db_write(sql_stmt);
	
	// get ID of new scan
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "select id from scan where start_time=%llu", starttime);
	db_read(sql_stmt, &scan_id, &get_int_cb);

	if ((strncmp(db_version, "0.8.5+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.7+", MAX_STRING_LEN) == 0)) {
		// set scan state to RUNNING
		sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "update scan set status='RUNNING' where id=%u", scan_id);
		db_write(sql_stmt);
	}
	
	return scan_id;
}

/* set listener */
int db_set_listener(uint32_t ip) {
	char sql_stmt[MAX_STMT_LEN];

	// add listener address (scan address) to scan
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "update scan set source_ip=%u where id=%u", ip, scan_id);
	db_write(sql_stmt);

	return 0;
}


/* add drone */
int db_add_drone(uint32_t ip, uint16_t port, uint32_t type) {
	char sql_stmt[MAX_STMT_LEN];
	uint32_t drone_id = 0;
	
	// add drone if not exists
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "insert or ignore into drone (ip) values (%u)", ip);
	db_write(sql_stmt);	

	// get ID of new drone
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "select id from drone where ip=%u", ip);
	db_read(sql_stmt, &drone_id, &get_int_cb);

	// drone usage
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "insert into drone_usage (drone_id, port, type, scan_id) values (%u, %u, %u, %u)", drone_id, port, type, scan_id);			
	db_write(sql_stmt);

	return 0;
}

/* add drone credentials */
int db_add_drone_credentials(uint8_t *uuid, char *username, char *password) {
	char sql_stmt[MAX_STMT_LEN];
	char uuid_str[UUID_STR_LEN], *p;
	int i;
	
	for (i=0, p = uuid_str; i <  UUID_LEN; i++, p += 2)
		sprintf(p, "%02x", uuid[i]);
	
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "insert into drone_credentials (uuid, username, password) values (%Q, %Q, %Q)", uuid_str, username, password);

	db_write(sql_stmt);

	return 0;
}

/* store result */
int db_store_tcp_result(uint32_t ip, uint16_t port) {
	char sql_stmt[MAX_STMT_LEN];
	uint32_t host_id = 0;
	
	// add host if not exists
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "insert or ignore into host (ip) values (%u)", ip);
	db_write(sql_stmt);	
	
	// get ID of new host
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "select id from host where ip=%u", ip);
	db_read(sql_stmt, &host_id, &get_int_cb);
	
	// add result
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "insert or ignore into result (port, host_id, scan_id) values (%u, %u, %u)", port, host_id, scan_id);
	db_write(sql_stmt);	

	return 0;
}


/* cancel scan */
int db_cancel_scan(mytime_t time) {
	char sql_stmt[MAX_STMT_LEN];
	
	// update end time
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "update scan set end_time=%llu where id=%u", time, scan_id);
	db_write(sql_stmt);

	if ((strncmp(db_version, "0.8.5+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.7+", MAX_STRING_LEN) == 0)) {
		// set scan state to CANCELED
		sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "update scan set status='CANCELED' where id=%u", scan_id);
		db_write(sql_stmt);
	}

	return 0;
}

/* finish scan */
int db_finish_scan(mytime_t time) {
	char sql_stmt[MAX_STMT_LEN];
	
	// update end time
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "update scan set end_time=%llu where id=%u", time, scan_id);
	db_write(sql_stmt);

	if ((strncmp(db_version, "0.8.5+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.7+", MAX_STRING_LEN) == 0)) {
		// set scan state to FINISHED if database allows it
		sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "update scan set status='FINISHED' where id=%u", scan_id);
		db_write(sql_stmt);
	}

	return 0;
}


/* get default TCP ports */
char *db_get_default_tcp_ports(void) {
	char sql_stmt[MAX_STMT_LEN];
		
	// get all default TCP ports
	if (strncmp(db_version, "0.7+", MAX_STRING_LEN) == 0) {
		sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "select port_string from default_ports");
	} else if ((strncmp(db_version, "0.8.3+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.5+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.7+", MAX_STRING_LEN) == 0)) {
		sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "select port_string from default_ports where protocol='TCP'");
	} else {
		MSG(MSG_ERR, "Unknown database version, cannot get default ports\n");
	}
	db_read(sql_stmt, default_port_string, &get_portlist_cb);

	// delete last comma
	default_port_string[strlen(default_port_string) - 1] = '\0';
			
	return default_port_string;
}

/* get drone credentials */
char **db_get_drone_credentials(uint8_t *uuid) {
	char sql_stmt[MAX_STMT_LEN];
	char uuid_str[UUID_STR_LEN], *p;
	int i;
	
	for (i=0, p = uuid_str; i <  UUID_LEN; i++, p += 2)
		sprintf(p, "%02x", uuid[i]);

	credentials = NULL;
	
	// get credentials for uuid
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "select username, password from drone_credentials where uuid=%Q", uuid_str);
	db_read(sql_stmt, credentials, &get_drone_credentials_cb);

	//fprintf(stderr, "credentials[0] = %s\n", credentials[0]);
	//fprintf(stderr, "credentials[1] = %s\n", credentials[1]);
	
	return credentials;
}

/* create report */
char *db_create_report(uint32_t id) {
	char sql_stmt[MAX_STMT_LEN];

	if (id == 0)
		id = scan_id;
	
	// get scan results (TCP only)
	if (strncmp(db_version, "0.7+", MAX_STRING_LEN) == 0) {
		sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "select r.port as port,h.ip as ip,s.name as name from result as r, host as h, services as s where scan_id=%u and r.host_id=h.id and r.port=s.port order by h.ip asc, r.port asc", id);
	} else if ((strncmp(db_version, "0.8.3+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.5+", MAX_STRING_LEN) == 0) || (strncmp(db_version, "0.8.7+", MAX_STRING_LEN) == 0)) {
		sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "select r.port as port,h.ip as ip,s.name as name from result as r, host as h, services as s where scan_id=%u and r.host_id=h.id and r.port=s.port and r.protocol=s.protocol and r.protocol='TCP' order by h.ip asc, r.port asc", id);
	}
	db_read(sql_stmt, 0, &create_report_cb);

	return 0;
}

/* set savepoint for temporary scans */
char *db_set_savepoint(void) {
	char sql_stmt[MAX_STMT_LEN];
	
	// add savepoint
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "begin transaction");
	db_write(sql_stmt);	

	return 0;
}

/* rollback to savepoint state */
char *db_rollback(void) {
	char sql_stmt[MAX_STMT_LEN];
	
	// rollback
	sqlite3_snprintf(MAX_STMT_LEN, sql_stmt, "rollback transaction");
	db_write(sql_stmt);	

	return 0;
}
