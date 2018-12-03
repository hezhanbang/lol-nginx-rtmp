
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

//handshake
ngx_int_t ngx_mysql_connect();
void ngx_mysql_recv_init_package(ngx_event_t *rev);
void ngx_mysql_send_auth_package(ngx_event_t *wev);
void ngx_mysql_recv_auth_result(ngx_event_t *rev);
void ngx_mysql_send_utf8Name(ngx_event_t *wev);
void ngx_mysql_recv_simple_result(ngx_event_t *rev);
ngx_int_t ngx_mysql_sha256(u_char *hash, u_char *buf, int len);
ngx_int_t ngx_mysql_sha1(u_char *hash, u_char *buf, int len);

ngx_int_t ngx_mysql_generateCmdPacket(enum mysqlCmdType type, char* cmdStr);
ngx_int_t ngx_mysql_write_packet(ngx_connection_t *cc, ngx_event_t *rev);
ngx_int_t ngx_mysql_read_packet(ngx_connection_t *cc, ngx_event_t *rev);


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
    ngx_mysql_connection.connected = 0;

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
ngx_mysql_query(char *sql)
{
    return NGX_OK;
    
    if(!ngx_mysql_connection.connected){
        ngx_mysql_connect();
        return NGX_OK;
    }
    return NGX_OK;
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


void
ngx_mysql_dummy_send(ngx_event_t *wev)
{
}


void
ngx_mysql_dummy_recv(ngx_event_t *rev)
{
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


//Reading Handshake Initialization Packet
void
ngx_mysql_recv_init_package(ngx_event_t *rev)
{
    ngx_connection_t           *cc;
    u_char                     *data;     
    int                         error, index, pos, len;

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
    // capability flagngx_mysql_recv_init_packages (lower 2 bytes) [2 bytes]
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

    cc->write->handler = ngx_mysql_send_auth_package;
    cc->read->handler = ngx_mysql_recv_auth_result;
    ngx_mysql_send_auth_package(cc->write);
    return;

fail:
    ngx_mysql_connect_close(cc);
}


void
ngx_mysql_send_auth_package(ngx_event_t *wev)
{
    ngx_connection_t *cc;
    ngx_mysql_conf_t *mycf;
    unsigned char    authResp[256];
    int              authRespLen=0;
    u_char           authSizeMark[9];  
    u_char          *respBuf;
    int              pos, index;
    int              pktLen=0;
    int              markSize=0; 

    cc = wev->data;

    if (cc->destroyed) {
        return;
    }

    if (wev->timedout) {
        cc->timedout = 1;
        goto fail;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    mycf = (ngx_mysql_conf_t*)ngx_cycle->conf_ctx[ngx_mysql_module.index];

    if(memcmp(ngx_mysql_connection.plugin, "mysql_native_password", 22)==0){
        unsigned char hash[SHA_DIGEST_LENGTH];
        unsigned char hash2[SHA_DIGEST_LENGTH+64];

        // scrambleHash = SHA1(scramble + SHA1(SHA1(password)))
        ngx_mysql_sha1(hash, mycf->pwd.data, mycf->pwd.len); //SHA1(password)
        ngx_mysql_sha1(hash2+20, hash, SHA_DIGEST_LENGTH);   //SHA1(SHA1(password))
        memcpy(hash2, ngx_mysql_connection.authData, 20);     //scramble + SHA1(SHA1(password))
        ngx_mysql_sha1(hash, hash2, 20 + SHA_DIGEST_LENGTH);

        // stage1Hash = SHA1(password)
        ngx_mysql_sha1(hash2, mycf->pwd.data, mycf->pwd.len);

        // token = scrambleHash XOR stage1Hash
        for(index=0; index<SHA_DIGEST_LENGTH; index++) {
            authResp[index] = hash2[index] ^ hash[index];
        }
        authRespLen=SHA_DIGEST_LENGTH;
    }else{
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "unknown auth plugin:%s", ngx_mysql_connection.plugin);
        goto fail;
    }

    ngx_mysql_connection.flags = clientProtocol41 |
        clientSecureConn |
        clientLongPassword |
        clientTransactions |
        clientLocalFiles |
        clientPluginAuth |
        clientMultiResults |
        (ngx_mysql_connection.flags & clientLongFlag);

    // encode length of the auth plugin data
    if(authRespLen <= 250) {
        authSizeMark[0]=authRespLen;
        markSize=1;
    }
    else if(authRespLen <= 0xffff) {
        authSizeMark[0]=0xfc;
        authSizeMark[1]=(u_char)authRespLen;
        authSizeMark[2]=(u_char)(authRespLen>>8);
        markSize=3;
    }
    else if(authRespLen <= 0xffffff) {
        authSizeMark[0]=0xfd;
        authSizeMark[1]=(u_char)authRespLen;
        authSizeMark[2]=(u_char)(authRespLen>>8);
        authSizeMark[3]=(u_char)(authRespLen>>16);
        markSize=4;
    }else {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "authRespLen is too big");
        goto fail;
    }
    if(markSize>1) {
        // if the length can not be written in 1 byte, it must be written as a
        // length encoded integer
        ngx_mysql_connection.flags |= clientPluginAuthLenEncClientData;
    }

    pktLen = 4 + 4 + 1 + 23 + mycf->user.len + 1 + markSize + authRespLen + 21 + 1;

    // To specify a db name
    ngx_mysql_connection.flags |= clientConnectWithDB;
    pktLen += mycf->dbName.len + 1;

    // Calculate packet length and get buffer with that size
    respBuf=(u_char*) ngx_mysql_connection.out->buf->pos;
    ngx_mysql_connection.out->buf->last = respBuf + 4 + pktLen;

    // ClientFlags [32 bit]
    respBuf[4] = (u_char)ngx_mysql_connection.flags;
    respBuf[5] = (u_char)(ngx_mysql_connection.flags >> 8);
    respBuf[6] = (u_char)(ngx_mysql_connection.flags >> 16);
    respBuf[7] = (u_char)(ngx_mysql_connection.flags >> 24);
    // MaxPacketSize [32 bit] (none)
    respBuf[8] = 0x00;
    respBuf[9] = 0x00;
    respBuf[10] = 0x00;
    respBuf[11] = 0x00;
    // Charset [1 byte]
    respBuf[12]=33;  //"utf8_general_ci": 33,
    // Filler [23 bytes] (all 0x00)
    pos = 13;
    for(; pos < 13+23; pos++) {
        respBuf[pos] = 0;
    }

    // User [null terminated string]
    memcpy(respBuf+pos,mycf->user.data, mycf->user.len);
    pos+=mycf->user.len;
    respBuf[pos] = 0x00;
    pos++;

    // Auth Data [length encoded integer]
    memcpy(respBuf+pos, authSizeMark, markSize);
    pos += markSize;

    memcpy(respBuf+pos, authResp, authRespLen);
    pos+=authRespLen;

    // Databasename [null terminated string]
    memcpy(respBuf+pos, mycf->dbName.data, mycf->dbName.len);
    pos += mycf->dbName.len;
    respBuf[pos] = 0x00;
    pos++;

    strcpy((char*)respBuf+pos, ngx_mysql_connection.plugin);
    pos+=strlen(ngx_mysql_connection.plugin);

    // Send Auth packet
    if(ngx_mysql_write_packet(cc, cc->write) != NGX_OK) {
        goto fail;
    }

    ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    return;
fail:
    ngx_mysql_connect_close(cc);
    return;
}


void
ngx_mysql_recv_auth_result(ngx_event_t *rev)
{
    ngx_connection_t           *cc;
    u_char                     *data;     
    int                         error, pos, len;

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

    if(0==data[0]){ //ok package

    } else {
        if(255==data[0]) { //err pakcage
            // Error Number [16 bit uint]
            //errno := binary.LittleEndian.Uint16(data[1:3])
            error = (int)( (uint32_t)data[1] | (uint32_t)data[2]<<8 );

            pos=3;
            // SQL State [optional: # + 5bytes string]
            if(data[3] == 0x23) {
                //sqlstate := string(data[4 : 4+5])
                pos = 9;
            }

            ngx_str_t errstr;
            errstr.data= data+pos;
            errstr.len=len-pos;
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "fail to auth mysql: code=%d msg=\"%V\"", error, &errstr);
        }
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "fail to auth mysql: code=%d", (int32_t)data[0]);
        goto fail;
    }

    cc->write->handler = ngx_mysql_send_utf8Name;
    cc->read->handler = ngx_mysql_recv_simple_result;
    ngx_mysql_send_utf8Name(cc->write);
    return;

fail:
    ngx_mysql_connect_close(cc);
}


void
ngx_mysql_send_utf8Name(ngx_event_t *wev)
{
    ngx_connection_t *cc;

    cc = wev->data;

    if (cc->destroyed) {
        return;
    }

    if (wev->timedout) {
        cc->timedout = 1;
        goto fail;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if(ngx_mysql_generateCmdPacket(comQuery, "SET NAMES utf8") != NGX_OK){
        goto fail;
    }

    // Send packet
    if(ngx_mysql_write_packet(cc, cc->write) != NGX_OK) {
        goto fail;
    }
    ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    return;

fail:
    ngx_mysql_connect_close(cc);
}



void
ngx_mysql_recv_simple_result(ngx_event_t *rev)
{
    ngx_connection_t           *cc;
    u_char                     *data;

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

    if(0!=data[0]){ //err package
        goto fail;
    }

    return;

fail:
    ngx_mysql_connect_close(cc);
}


ngx_int_t
ngx_mysql_sha256(u_char *hash, u_char *buf, int len)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buf, len);
    SHA256_Final(hash, &sha256);

    return NGX_OK;
}


ngx_int_t
ngx_mysql_sha1(u_char *hash, u_char *buf, int len)
{
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, buf, len);
    SHA1_Final(hash, &sha1);

    return NGX_OK;
}


ngx_int_t
ngx_mysql_generateCmdPacket(enum mysqlCmdType type, char* cmdStr)
{
    int         pktLen;
    u_char      *data;

    data = ngx_mysql_connection.out->buf->pos;

    // Reset Packet Sequence
	ngx_mysql_connection.sequence = 0;
	pktLen = 1 + strlen(cmdStr);

	// Add command byte
	data[4] = type;

	// Add arg
	strcpy((char*)data+5, cmdStr);

    ngx_mysql_connection.out->buf->last = data + pktLen + 4;
    return NGX_OK;
}

ngx_int_t
ngx_mysql_write_packet(ngx_connection_t *cc, ngx_event_t *rev)
{
    ngx_chain_t                        *chain;
    int                                 pktLen;
    u_char                             *data;
    
    pktLen = ngx_mysql_connection.out->buf->last - ngx_mysql_connection.out->buf->pos - 4;
    data = ngx_mysql_connection.out->buf->pos;

    data[0] = (u_char)pktLen;
    data[1] = (u_char)(pktLen >> 8);
    data[2] = (u_char)(pktLen >> 16);
    data[3] = ngx_mysql_connection.sequence;

    chain = cc->send_chain(cc, ngx_mysql_connection.out, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ngx_cycle->log, 0, "mysql connection write %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        cc->error = 1;
        return NGX_ERROR;
    }
    ngx_mysql_connection.sequence++;
    return NGX_OK;
}


ngx_int_t
ngx_mysql_read_packet(ngx_connection_t *cc, ngx_event_t *rev)
{
    ngx_buf_t  *b;
    ngx_int_t   n;
    int         pktLen;
    u_char     *data;

    b = ngx_mysql_connection.in->buf;
    n = cc->recv(cc, b->pos, b->end - b->pos);
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