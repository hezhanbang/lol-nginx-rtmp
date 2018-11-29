
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include "ngx_mysql.h"


#define MYSQL_TIMEOUT (3)

#define clientLongPassword                  (0x1<<0)
#define clientFoundRows                     (0x1<<1)
#define clientLongFlag                      (0x1<<2)
#define clientConnectWithDB                 (0x1<<3)
#define clientNoSchema                      (0x1<<4)
#define clientCompress                      (0x1<<5)
#define clientODBC                          (0x1<<6)
#define clientLocalFiles                    (0x1<<7)
#define clientIgnoreSpace                   (0x1<<8)
#define clientProtocol41                    (0x1<<9)
#define clientInteractive                   (0x1<<10)
#define clientSSL                           (0x1<<11)
#define clientIgnoreSIGPIPE                 (0x1<<12)
#define clientTransactions                  (0x1<<13)
#define clientReserved                      (0x1<<14)
#define clientSecureConn                    (0x1<<15)
#define clientMultiStatements               (0x1<<16)
#define clientMultiResults                  (0x1<<17)
#define clientPSMultiResults                (0x1<<18)
#define clientPluginAuth                    (0x1<<19)
#define clientConnectAttrs                  (0x1<<20)
#define clientPluginAuthLenEncClientData    (0x1<<21)
#define clientCanHandleExpiredPasswords     (0x1<<22)
#define clientSessionTrack                  (0x1<<23)
#define clientDeprecateEOF                  (0x1<<24)


enum mysqlCmdType {
	comQuit = 1,
	comInitDB,
	comQuery,
	comFieldList,
	comCreateDB,
	comDropDB,
	comRefresh,
	comShutdown,
	comStatistics,
	comProcessInfo,
	comConnect,
	comProcessKill,
	comDebug,
	comPing,
	comTime,
	comDelayedInsert,
	comChangeUser,
	comBinlogDump,
	comTableDump,
	comConnectOut,
	comRegisterSlave,
	comStmtPrepare,
	comStmtExecute,
	comStmtSendLongData,
	comStmtClose,
	comStmtReset,
	comSetOption,
	comStmtFetch
};


char *ngx_set_mysql_info(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_mysql_module_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_mysql_init_process(ngx_cycle_t *cycle);
ngx_int_t ngx_mysql_query(ngx_cycle_t *cycle, char *sql);
ngx_int_t ngx_mysql_connect(ngx_cycle_t *cycle);
ngx_int_t ngx_mysql_writeCommandPacketStr(enum mysqlCmdType type, char* cmdStr);
ngx_int_t ngx_mysql_write_packet(int sock, u_char *data, int len);
ngx_int_t ngx_mysql_read_packet(int sock, u_char *buf, int cap);
ngx_int_t ngx_mysql_read(int sock, u_char *buf, int cap);
ngx_int_t ngx_mysql_sha256(u_char *hash, u_char *buf, int len);
ngx_int_t ngx_mysql_sha1(u_char *hash, u_char *buf, int len);


ngx_mysql_ctx_t ngx_mysql_connection;


static ngx_command_t  ngx_mysql_commands[] = {

    { ngx_string("mysql"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE5,
      ngx_set_mysql_info,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_mysql_module_ctx = {
    ngx_string("mysql"),
    ngx_mysql_module_create_conf,
    NULL
};


ngx_module_t  ngx_mysql_module = {
    NGX_MODULE_V1,
    &ngx_mysql_module_ctx,                  /* module context */
    ngx_mysql_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_mysql_init_process,                 /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


char *
ngx_set_mysql_info(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mysql_conf_t   *mycf = conf;
    ngx_str_t          *value;
    u_char             *p;
    ngx_int_t          n;

    value = cf->args->elts;

    //ip
    p = ngx_pstrdup(cf->cycle->pool, value+1);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }
    mycf->ip.data = p;
    mycf->ip.len= value[1].len;

    //port
    n = ngx_atoi(value[2].data, value[2].len);
    if (n == NGX_ERROR) {
        return "invalid number";
    }
    mycf->port = n;

    //user
    p = ngx_pstrdup(cf->cycle->pool, value+3);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }
    mycf->user.data = p;
    mycf->user.len= value[3].len;

    //pwd
    p = ngx_pstrdup(cf->cycle->pool, value+4);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }
    mycf->pwd.data = p;
    mycf->pwd.len= value[4].len;

    //dbName
    p = ngx_pstrdup(cf->cycle->pool, value+5);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }
    mycf->dbName.data = p;
    mycf->dbName.len= value[5].len;

    //connected
    mycf->connected = 0;

    return NGX_CONF_OK;
}


static void *
ngx_mysql_module_create_conf(ngx_cycle_t *cycle)
{
    ngx_mysql_conf_t  *mycf;

    mycf = ngx_pcalloc(cycle->pool, sizeof(ngx_mysql_conf_t));
    if (mycf == NULL) {
        return NULL;
    }

    mycf->port = NGX_CONF_UNSET;

    //init mysql connection.
    ngx_mysql_connection.sock = -1;
    ngx_mysql_connection.sequence = 0;
    ngx_mysql_connection.pool = NULL;

    return mycf;
}


static ngx_int_t
ngx_mysql_init_process(ngx_cycle_t *cycle)
{
    return ngx_mysql_connect(cycle);
}


ngx_int_t
ngx_mysql_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


void
ngx_mysql_free_peer(ngx_peer_connection_t *pc, void *data,
            ngx_uint_t state)
{
}


ngx_int_t
ngx_mysql_connect(ngx_cycle_t *cycle)
{
    ngx_mysql_conf_t        *mycf;
    ngx_int_t                rc;
    ngx_peer_connection_t   *pc;
    ngx_addr_t              *addr;
    char                     temp[32];
    int                      len;
    int                      ok = 0;

    mycf = (ngx_mysql_conf_t*)cycle->conf_ctx[ngx_mysql_module.index];
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, 
        "hebang do ngx_mysql_connect [ip=%V port=%d user=%V pwd=%V database=%V",
        &mycf->ip,
        mycf->port,
        &mycf->user,
        &mycf->pwd,
        &mycf->dbName
        );

    ngx_mysql_connection.pool = ngx_create_pool(4096, cycle->log);
    if (ngx_mysql_connection.pool == NULL) {
        goto error;
    }

    pc = ngx_pcalloc(ngx_mysql_connection.pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        goto error;
    }

    pc->log = cycle->log;
    pc->log_error = NGX_ERROR_ERR;
    pc->get = ngx_mysql_get_peer;
    pc->free = ngx_mysql_free_peer;

    addr = ngx_palloc(ngx_mysql_connection.pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        goto error;
    }
    len = ngx_sprintf(temp, "%V:%d", &mycf->ip, mycf->port) - temp;
    rc = ngx_parse_addr_port(ngx_mysql_connection.pool, addr, temp, len);
    if(NGX_OK!=rc) {
        goto error;
    }
    pc->sockaddr = addr->sockaddr;
    pc->socklen = addr->socklen;
    pc->name = &addr->name;

    /* connect */
    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, cycle->log, 0, "fail to connect mysql");
        ngx_close_connection(pc->connection);
        goto error;
    }

    ok = 1;
error:
    if (pool && !ok) {
        ngx_destroy_pool(pool);
    }

    return NGX_OK;
}
