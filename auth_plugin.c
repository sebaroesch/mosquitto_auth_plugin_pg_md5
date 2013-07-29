#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <libpq-fe.h>
#include <md5.h>

typedef char * string;

int mosquitto_auth_plugin_version(void)
{
    return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
    return MOSQ_ERR_SUCCESS;
}

//int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access)
int mosquitto_auth_acl_check(void *user_data, const char *username, const char *topic, int access)
{
    int ulen = strlen(username);

    if(!strcmp(username, "SERVER")) {

        // server can read /#/status
        if (access == MOSQ_ACL_READ){
            string suffix="/status";
            // find / in topic
            char *pos = strrchr(topic,'/');
            // compare
            if (!strcmp(suffix, pos)) {
                return MOSQ_ERR_SUCCESS;
            }
        }
        else {
            // TODO restrict writing to /#/warning
            return MOSQ_ERR_SUCCESS;
        }

    } else {

        // NO Server --> client
        if(access == MOSQ_ACL_READ){
            // users can read topic /<username>/warning
            string suffix="/warning";
            // name of allowed topic
            string t_allowed= malloc(ulen + strlen(suffix)+1) ; /* +1 DFTTZ! */
            strcpy(t_allowed,username) ;
            strcat(t_allowed,suffix) ;
            // compare
            if (!strcmp(t_allowed, topic)) {
                return MOSQ_ERR_SUCCESS;
            }
        } else {
            // users can write to topic /<username>/status
            string suffix="/status";
            // name of allowed topic
            string t_allowed=malloc(ulen + strlen(suffix)+1) ; /* +1 DFTTZ! */
            strcpy(t_allowed,username) ;
            strcat(t_allowed,suffix) ;
            // compare
            if (!strcmp(t_allowed, topic)) {
                return MOSQ_ERR_SUCCESS;
            }
        }
    }
    return MOSQ_ERR_AUTH;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
{
    // SERVER
    if(!strcmp(username, "SERVER") && password && !strcmp(password, "abc")){
        return MOSQ_ERR_SUCCESS;
    }
    // user
    // lookup hashed pw in DB
    PGconn          *conn;
    PGresult        *res;
    int ulen = strlen(username);

    conn = PQconnectdb("dbname=abc host=localhost user=abc password=def");

    if (PQstatus(conn) == CONNECTION_BAD) {
            puts("Unable to connect to the database");
            return MOSQ_ERR_AUTH;
    }

    // statement to get hash of users pw / token
    string stmt = "SELECT * FROM public.\"user\" where username = '";
    string stmt_suffix = "'";
    // name of allowed topic
    // TODO --> prevent SQL injection
    string stmt_w_user=malloc(strlen(stmt) + ulen + strlen(stmt_suffix) + 1) ; /* +1 DFTTZ! */
    strcpy(stmt_w_user,stmt) ;
    strcat(stmt_w_user,username) ;
    strcat(stmt_w_user,stmt_suffix) ;

    res = PQexec(conn, stmt_w_user);

    // got result
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {

        // DO MD5()
        unsigned char hash_ret[16];
  	MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, password, strlen(password));
		MD5_Final(hash_ret, &ctx);
		char tmp[3]={'\0'};
		char hash[33]={'\0'};
		int i=0;
		for (; i<16; i++) {
			sprintf(tmp, "%2.2x", hash_ret[i]);
			strcat(hash, tmp);
		}

        if(!strcmp(hash, PQgetvalue(res, 0, 2))){
            return MOSQ_ERR_SUCCESS;
        }
    }

    PQclear(res);
    PQfinish(conn);

    return MOSQ_ERR_AUTH;

}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len)
{
    return MOSQ_ERR_AUTH;
}
