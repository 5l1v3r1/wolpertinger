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


#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

#define	DATABASE				"wolpertinger.db"
#define DATABASE_HOME			"/.wolpertinger/"

#define MAX_STMT_LEN			8192
#define MAX_STRING_LEN			256
#define MAX_DEFAULT_PORTSTR_LEN	4096

int db_open(void);
int db_find_version(void);
int db_exec(char *sql_stmt);
int db_close(void);

int db_create_scan(mytime_t starttime, mytime_t estendtime, struct info *scan_info);
int db_set_listener(uint32_t ip);
int db_cancel_scan(mytime_t time);
int db_finish_scan(mytime_t time);
int db_add_drone(uint32_t ip, uint16_t port, uint32_t type);
int db_add_drone_credentials(uint8_t *uuid, char *username, char *password);
char **db_get_drone_credentials(uint8_t *uuid);
int db_store_tcp_result(uint32_t ip, uint16_t port);
char *db_get_default_tcp_ports(void);
char *db_create_report(uint32_t scan_id);
char *db_set_savepoint(void);
char *db_rollback(void);

#endif

