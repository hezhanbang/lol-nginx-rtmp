
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include "ngx_rtmp.h"
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

ngx_int_t ngx_mysql_query(ngx_cycle_t *cycle, char *sql);
ngx_int_t ngx_mysql_writeCommandPacketStr(enum mysqlCmdType type, char* cmdStr);
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
    &ngx_mysql_module_ctx,                 /* module context */
    ngx_mysql_commands,                    /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
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


void
ngx_mysql_connect_close(ngx_connection_t *cc)
{
    ngx_pool_t      *pool;

    if (cc->destroyed) {
        return;
    }

    cc->destroyed = 1;

    pool = cc->pool;
    ngx_close_connection(cc);
    ngx_destroy_pool(pool);
}


ngx_int_t
ngx_mysql_read_packet(ngx_connection_t *cc, ngx_event_t *rev)
{
    ngx_buf_t  *b;
    ngx_int_t   n;
    int         pktLen;
    u_char     *data;

    b = ngx_mysql_connection.in->buf;
    n = cc->recv(cc, b->last, b->end - b->last);
    if (n == NGX_ERROR || n == 0) {
        ngx_mysql_connect_close(cc);
        return NGX_ERROR;
    }
     if (n == NGX_AGAIN) {
        ngx_add_timer(rev, ngx_mysql_connection.timeout);
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_mysql_connect_close(cc);
        }
        return NGX_OK;
    }

    if(n<4){
        return NGX_ERROR;
    }
    data=b->pos;

    // packet length [24 bit]
	pktLen = (int)( (uint32_t)(data[0]) | ((uint32_t)(data[1]))<<8 | ((uint32_t)(data[2]))<<16);
    // check packet sync [8 bit]
    if(data[3] != ngx_mysql_connection.sequence) {
        return NGX_ERROR;
    }
    ngx_mysql_connection.sequence++;

    if(n < 4+ pktLen){
        return NGX_ERROR;
    }
    b->last = b->pos + 4 + pktLen;
    return NGX_OK;
}


void
ngx_mysql_dummy_send(ngx_event_t *wev)
{
}


void
ngx_mysql_dummy_recv(ngx_event_t *rev)
{
}


void ngx_mysql_send_auth_package(ngx_event_t *wev)
{

}


//Reading Handshake Initialization Packet
void
ngx_mysql_recv_init_package(ngx_event_t *rev)
{
    ngx_connection_t           *cc;
    u_char                     *data;     
    int                         error, index, pos, len;
    int                         ok = 0;

    cc = rev->data;

    if (cc->destroyed) {
        return;
    }

    if (rev->timedout) {
        cc->timedout = 1;
        goto fail;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if(NGX_OK != ngx_mysql_read_packet(cc, rev)){
        goto fail;
    }
    //got package now
    data = ngx_mysql_connection.in->buf->pos + 4;
    len = ngx_mysql_connection.in->buf->last - data;

    if(0xff==data[0]){
        ngx_str_t errstr;
        error = (int)( (uint32_t)data[1] | (uint32_t)data[2]<<8 );
        errstr.data= data+3;
        errstr.len=len-3;
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "fail to connect mysql: code=%d msg=\"%V\"", error, &errstr);
        goto fail;
    }
    // protocol version [1 byte]
    if(data[0] < 10){
        goto fail;
    }

    // server version [null terminated string]
    // connection id [4 bytes]
    for(index=1; index< len-2; index++){
        if(data[index]=='\0') {
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "mysql version: %s", (char*)data+1);
            break;
        }
    }
    pos = index + 1 + 4;
    // first part of the password cipher [8 bytes]
    memcpy(ngx_mysql_connection.authData, data+pos, 8);
    ngx_mysql_connection.authLen=8;
    // (filler) always 0x00 [1 byte]
    pos += 8 + 1;
    // capability flags (lower 2 bytes) [2 bytes]
    ngx_mysql_connection.flags = (uint32_t)data[pos] | (uint32_t)(data[pos+1]<<8);
    //check clientProtocol41
    if((ngx_mysql_connection.flags & clientProtocol41) == 0){
        goto fail;
    }
    pos+=2;

    if(len>pos){
        // character set [1 byte]
        // status flags [2 bytes]
        // capability flags (upper 2 bytes) [2 bytes]
        // length of auth-plugin-data [1 byte]
        // reserved (all [00]) [10 bytes]
        pos += 1 + 2 + 2 + 1 + 10;
        memcpy(ngx_mysql_connection.authData+8, data+pos, 12);
        ngx_mysql_connection.authLen+=12;
        pos += 13;

        // EOF if version (>= 5.5.7 and < 5.5.10) or (>= 5.6.0 and < 5.6.2)
        // \NUL otherwise
        for(index=pos; index<len; index++) {
            if(data[index]=='\0'){
                break;
            }
        }
        if(index<len){
                strcpy(ngx_mysql_connection.plugin, (char*)data+pos);
        }else{
            memcpy(ngx_mysql_connection.plugin, (char*)data+pos, len-pos);
            ngx_mysql_connection.plugin[len-pos]='\0';
        }
        if(ngx_mysql_connection.plugin[0]=='\0'){
            strcpy(ngx_mysql_connection.plugin, "mysql_native_password");
        }
    }

    ok = 1;
fail:
    if(!ok) {
        ngx_mysql_connect_close(cc);
        return;
    }

    cc->write->handler = ngx_mysql_send_auth_package;
    cc->read->handler = ngx_mysql_dummy_recv;
}


ngx_int_t
ngx_mysql_connect()
{
    ngx_mysql_conf_t        *mycf;
    ngx_int_t                rc;
    ngx_peer_connection_t   *pc;
    ngx_connection_t        *cc;
    u_char                   data[32];
    int                      ok = 0;
    ngx_url_t               *url;
    int                      len;
    ngx_chain_t             *pl;

    mycf = (ngx_mysql_conf_t*)ngx_cycle->conf_ctx[ngx_mysql_module.index];
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, 
        "hebang do ngx_mysql_connect [ip=%V port=%d user=%V pwd=%V database=%V]",
        &mycf->ip,
        mycf->port,
        &mycf->user,
        &mycf->pwd,
        &mycf->dbName
        );

    ngx_mysql_connection.sequence=0;
    //create pool
    ngx_mysql_connection.pool = ngx_create_pool(4096, ngx_cycle->log);
    if (ngx_mysql_connection.pool == NULL) {
        goto error;
    }

    //url
    url = ngx_pcalloc(ngx_mysql_connection.pool, sizeof(ngx_url_t));
    if (url == NULL) {
        goto error;
    }
    len = ngx_sprintf(data, "%V:%d", &mycf->ip, mycf->port) - data;

    url->url.len = len;
    url->url.data = data;
    url->default_port = 3306;
    url->uri_part = 1;

    rc = ngx_parse_url(ngx_mysql_connection.pool, url);
    if(NGX_OK != rc) {
        goto error;
    }
    rtmpSetStr(url->addrs->name, "mysql_server");

    //create connection
    pc = ngx_pcalloc(ngx_mysql_connection.pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        goto error;
    }

    pc->log = ngx_cycle->log;
    pc->log_error = NGX_ERROR_ERR;
    pc->get = ngx_mysql_get_peer;
    pc->free = ngx_mysql_free_peer;

    pc->sockaddr = url->addrs->sockaddr;
    pc->socklen = url->addrs->socklen;
    pc->name = &url->addrs->name;

    /* connect */
    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "fail to connect mysql");
        ngx_close_connection(pc->connection);
        goto error;
    }

    cc = pc->connection;
    cc->pool = ngx_mysql_connection.pool;
    cc->write->handler = ngx_mysql_dummy_send;
    cc->read->handler = ngx_mysql_recv_init_package;

    //create in chain
    pl = ngx_alloc_chain_link(ngx_mysql_connection.pool);
    if (pl == NULL) {
        goto error;
    }
    pl->buf = ngx_create_temp_buf(ngx_mysql_connection.pool, 256);
    if (pl->buf == NULL) {
        goto error;
    }
    ngx_mysql_connection.in = pl;

    //create out chain
    pl = ngx_alloc_chain_link(ngx_mysql_connection.pool);
    if (pl == NULL) {
        goto error;
    }
    pl->buf = ngx_create_temp_buf(ngx_mysql_connection.pool, 256);
    if (pl->buf == NULL) {
        goto error;
    }
    ngx_mysql_connection.out = pl;

    ok = 1;
error:
    if(!ok){
        if (ngx_mysql_connection.pool) {
            ngx_destroy_pool(ngx_mysql_connection.pool);
        }
        return NGX_ERROR;
    }
    return NGX_OK;
}
