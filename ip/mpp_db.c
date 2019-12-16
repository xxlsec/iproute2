/*
 * Multi-party Database functions
 * 
 * Copyright (C) 2019 XXLSEC LTD
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */

#include <arpa/inet.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <uuid/uuid.h>
#include "mpp_db.h"
#include "log.h"


int ismppdbavailable(const char * filename) {
    FILE *file;
    if ( (file = fopen(filename, "r") ) ){
        fclose(file);
        return 1;
    }
    return 0;
}

/* Callback for 'config' table display
 */
int configcallback(void *NotUsed, int argc, char **argv, 
                    char **azColName) {
    NotUsed = 0;
    log_trace("[%d] Payload: %s",getpid(),argv[0]);
    log_trace("[%d] HUB IP: %s HUB PORT: %s",getpid(),argv[1],argv[2]);
    return 0;
}

/* Callback for 'peers' table display
 */
int peerscallback(void *NotUsed, int argc, char **argv, 
                    char **azColName) {
    NotUsed = 0;
    if( strlen(argv[0])>0)
		log_trace("[%d] Constellation entity: %s",getpid(),argv[0]);
    return 0;
}

/* Show 'config' table and callback to show it
 */
int showmyconfig() 
{
	log_trace("[%d] My configuration: %s",getpid());
	
	sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open( MPP_DB_FILE_ENCRYPTED , &db);
    sqlite3_exec(db, "pragma journal_mode = WAL", NULL, NULL, NULL);    
    if (rc != SQLITE_OK) {
        log_error("[%d] Cannot open database: %s ",getpid(),sqlite3_errmsg(db) );
        sqlite3_close(db);
        return 1;
    }    
    char *sql = "SELECT nickname,hub1,hub1_port FROM config";
    rc = sqlite3_exec(db, sql, configcallback, 0, &err_msg);
    if (rc != SQLITE_OK ) {
		log_error("[%d] Failed to select data ",getpid() );
		log_error("[%d] SQL error: %s ",getpid(),err_msg );
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    } 
    sqlite3_close(db);
    return 0;
}

/* Key debug function
 */
int showmulticastkey()
{
	char debug[200];
	getpayloadfield(MKEY, debug);
	log_trace("[%d] Multicast key: %s ",getpid(),debug );
	return 0;
}

/* Key debug function
 */
int showgroupkey()
{
	char debug[200];
	getpayloadfield(GKEY, debug);
	log_trace("[%d] Group key: %s ",getpid(),debug );
	return 0;
}


/* Show constellation members from 'peers' table
 */
int showconstellation(int (*callback)(void*,int,char**,char**))
{
	sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open( MPP_DB_FILE_DECRYPTED , &db);
    sqlite3_exec(db, "pragma journal_mode = WAL", NULL, NULL, NULL);    
    if (rc != SQLITE_OK) {
        log_error("[%d] Cannot open database: %s ",getpid(),sqlite3_errmsg(db) );
        sqlite3_close(db);
        return 1;
    }    
    char *sql = "SELECT nick_name FROM peers";
    rc = sqlite3_exec(db, sql, callback, 0, &err_msg);
    if (rc != SQLITE_OK ) {
		log_error("[%d] Failed to select data ",getpid() );
		log_error("[%d] SQL error: %s ",getpid(),err_msg );
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    } 
    sqlite3_close(db);
    return 0;
}

/* Get single field from payload ('nickname') from config table
 * See defines in mpp_db.h for field index
 */
int getpayloadfield(int index, char* fielddata)
{
	char payloadbuffer[1024];
	char arrayelements[10][1024];
	getpayload(payloadbuffer);
	char* token = strtok(payloadbuffer, ","); 
    int n=0;
    while (token != NULL) { 
		strcpy(arrayelements[n++], token);
        token = strtok(NULL, ","); 
    } 	    
    for (int i=0; i < n; i++) 
    {
		if ( i == index ) 
			sprintf(fielddata,"%s", arrayelements[i]);
	}
	return 0;
}
/* Get payload from 'peers' table
 */
int getpeerspayload(char *payload) {

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc = sqlite3_open( MPP_DB_FILE_DECRYPTED , &db);
    if (rc != SQLITE_OK) {
        log_error("[%d] Cannot open database: %s ",getpid(),sqlite3_errmsg(db) );
        sqlite3_close(db);
        return 1;
    }
    char *sql="SELECT nick_name FROM peers";
    rc = sqlite3_prepare(db, sql, strlen(sql), &stmt, 0);
    if(rc!=SQLITE_OK) {
        log_error("[%d] DB error %d: %s ",getpid(),rc, sqlite3_errmsg(db) );
         } else while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
                 switch(rc) {
                 case SQLITE_BUSY:
                         log_error("[%d] DB busy",getpid());
                         break;
                 case SQLITE_ERROR:
                        log_error("[%d] DB error: %s ",getpid(),sqlite3_errmsg(db) );
                        break;
                 case SQLITE_ROW:
                         {
                                 int n = sqlite3_column_count(stmt);
                                 int i;
                                 for(i=0; i<n; i++) {
                                         switch(sqlite3_column_type(stmt, i)) {
                                         case SQLITE_TEXT:
                                                 if ( strcmp(sqlite3_column_name(stmt, i),"nick_name") == 0 ) {
                                                    strcpy(payload,(const char*)sqlite3_column_text(stmt, i) );
                                                    }
                                                 break;
                                         case SQLITE_INTEGER:
                                                 printf("%d", sqlite3_column_int(stmt, i));
                                                 break;
                                         case SQLITE_FLOAT:
                                                 printf("%f", sqlite3_column_double(stmt, i));
                                                 break;
                                         case SQLITE_BLOB:
                                                 printf("(blob)");
                                                 break;
                                         case SQLITE_NULL:
                                                 printf("(null)");
                                                 break;
                                         default:
                                                 printf("(unknown: %d)", sqlite3_column_type(stmt, i));
                                         }
                                 }
                         }
                         break;
                 }
         }
         sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

/* Get single field from payload ('nick_name') from peers table
 * See defines in mpp_db.h for field index
 */
int getpeerspayloadfield(int index, char* fielddata)
{
    char payloadbuffer[1024];
    char arrayelements[10][1024];
    getpeerspayload(payloadbuffer);
    char* token = strtok(payloadbuffer, ",");
    int n=0;
    while (token != NULL) {
        strcpy(arrayelements[n++], token);
        token = strtok(NULL, ",");
    }
    for (int i=0; i < n; i++)
    {
        if ( i == index )
            sprintf(fielddata,"%s", arrayelements[i]);
    }
    return 0;
}


/* Create empty payload placeholder to 'config' table
 */
int initemptypayload()
{
	char *payload="[NICK],[IP],[MKEY],[GKEY],[MACADDR],[MACSEC KEY],[MACSEC IP]";
	writepayload(payload);
	return 0;
}

/* Write payload to 'config' table
 */
int writepayload(char *payload)
{
	log_trace("[%d] Storing new payload: %s",getpid(),payload);
	sqlite3 *db;
    int rc = sqlite3_open( MPP_DB_FILE_ENCRYPTED , &db);
    if (rc != SQLITE_OK) {
        log_error("[%d] Cannot open database: %s ",getpid(),sqlite3_errmsg(db) );
        sqlite3_close(db);
        return 1;
    }
	sqlite3_stmt *stmt;
	const char *pzTest;
	char *szSQL;
	szSQL = "UPDATE config SET nickname=? WHERE rowid=1"; 
	rc = sqlite3_prepare(db, szSQL, strlen(szSQL), &stmt, &pzTest);
	if( rc == SQLITE_OK ) {
		sqlite3_bind_text(stmt, 1, payload, strlen(payload), 0);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	} else {
		log_error("[%d] Update error: %s ",getpid(),sqlite3_errmsg(db) );
	}
	sqlite3_close(db);
	return 0;
	
}

/* Alters comma separated payload in 'nickname' column in 'config' table
 * and writes it back to DB. See mpp_db.h defines for field order.
 */
int setpayload(int index, char* payload)
{
	char payloadbuffer[1024];
	char arrayelements[10][1024];
	char newpayloadbuffer[1024];	
	
	if (index == MKEY && strlen(payload) != 64) 
		log_warn("[%d] !! Check your MKEY lenght: %d !!",getpid(),strlen(payload));
	if (index == GKEY && strlen(payload) != 64) 
		log_warn("[%d] !! Check your GKEY lenght: %d !!",getpid(),strlen(payload));
	
	log_trace("[%d] Set setpayload %d: %s",getpid(),index, payload);
	getpayload(payloadbuffer);
	log_trace("[%d] Payload: %s",getpid(),payloadbuffer);
    char* token = strtok(payloadbuffer, ","); 
    int n=0;
    while (token != NULL) { 
		strcpy(arrayelements[n++], token);
        token = strtok(NULL, ","); 
    } 	    
    for (int i=0; i < n; i++) 
    {
		if ( i == index )
			sprintf(newpayloadbuffer + strlen(newpayloadbuffer),payload);
		else
			sprintf(newpayloadbuffer + strlen(newpayloadbuffer),arrayelements[i]);
		if(i<n-1)
			sprintf(newpayloadbuffer + strlen(newpayloadbuffer),",");
	}
	log_trace("[%d] Payload: %s",getpid(),newpayloadbuffer);
	writepayload(newpayloadbuffer);
	return 0;
}


/* Get payload from 'config' table
 */
int getpayload(char *payload) {

	sqlite3 *db;
	sqlite3_stmt *stmt;
    int rc = sqlite3_open( MPP_DB_FILE_ENCRYPTED , &db);
    if (rc != SQLITE_OK) {
        log_error("[%d] Cannot open database: %s ",getpid(),sqlite3_errmsg(db) );
        sqlite3_close(db);
        return 1;
    }
    char *sql="SELECT nickname FROM config";
    rc = sqlite3_prepare(db, sql, strlen(sql), &stmt, 0);
    if(rc!=SQLITE_OK) {
		log_error("[%d] DB error %d: %s ",getpid(),rc, sqlite3_errmsg(db) );         
         } else while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
                 switch(rc) {
                 case SQLITE_BUSY:
						 log_error("[%d] DB busy",getpid());                 
                         break;
                 case SQLITE_ERROR:
						log_error("[%d] DB error: %s ",getpid(),sqlite3_errmsg(db) );
                        break;
                 case SQLITE_ROW:
                         {
                                 int n = sqlite3_column_count(stmt);
                                 int i;
                                 for(i=0; i<n; i++) {
                                         switch(sqlite3_column_type(stmt, i)) {
                                         case SQLITE_TEXT:
                                                 if ( strcmp(sqlite3_column_name(stmt, i),"nickname") == 0 ) {
													strcpy(payload,(const char*)sqlite3_column_text(stmt, i) );
													}													
                                                 break;
                                         case SQLITE_INTEGER:
                                                 printf("%d", sqlite3_column_int(stmt, i));
                                                 break;
                                         case SQLITE_FLOAT:
                                                 printf("%f", sqlite3_column_double(stmt, i));
                                                 break;
                                         case SQLITE_BLOB:
                                                 printf("(blob)");
                                                 break;
                                         case SQLITE_NULL:
                                                 printf("(null)");
                                                 break;
                                         default:
                                                 printf("(unknown: %d)", sqlite3_column_type(stmt, i));
                                         }
                                 }
                         }
                         break;
                 }
         }
         sqlite3_finalize(stmt);
    sqlite3_close(db);
	return 0;
}







