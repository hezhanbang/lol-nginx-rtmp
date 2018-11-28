
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <nginx.h>
#include "ngx_mysql.h"


char *ngx_set_mysql_info(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_mysql_module_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_mysql_init_process(ngx_cycle_t *cycle);
ngx_int_t ngx_mysql_query(ngx_cycle_t *cycle, char *sql);
ngx_int_t ngx_mysql_connect(ngx_cycle_t *cycle);
ngx_int_t ngx_mysql_write_packet(int sock, u_char *data, int len);
ngx_int_t ngx_mysql_read_packet(int sock, u_char *buf, int cap);
ngx_int_t ngx_mysql_read(int sock, u_char *buf, int cap);
ngx_int_t ngx_mysql_sha256(u_char *hash, u_char *buf, int len);
ngx_int_t ngx_mysql_sha1(u_char *hash, u_char *buf, int len);


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
    ngx_mysql_connection.sequence = 0;

    return mycf;
}


static ngx_int_t
ngx_mysql_init_process(ngx_cycle_t *cycle)
{
    return ngx_mysql_connect(cycle);
}


ngx_int_t
ngx_mysql_query(ngx_cycle_t *cycle, char *sql)
{
    ngx_mysql_conf_t *mycf = (ngx_mysql_conf_t*)cycle->conf_ctx[ngx_mysql_module.index];

    if(0 == mycf->connected) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_mysql_connect(ngx_cycle_t *cycle)
{
    ngx_mysql_conf_t   *mycf;
    int                 ret;
    int                 sock;
    u_char              temp[255];
    struct sockaddr_in  sin;
    fd_set              fsetwrite;
    struct timeval      tv;
    ngx_int_t           failed = 1;
    int                 error;
    socklen_t           len;
    uint32_t            flags;
    int                 index;
    int                 pos = 0;
    u_char              authData[8+12];
    int                 authLen;
    char                plugin[32];

    mycf = (ngx_mysql_conf_t*)cycle->conf_ctx[ngx_mysql_module.index];
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, 
        "hebang do ngx_mysql_connect [ip=%V port=%d user=%V pwd=%V database=%V",
        &mycf->ip,
        mycf->port,
        &mycf->user,
        &mycf->pwd,
        &mycf->dbName
        );

    //use block socket to connect mysql server.
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock<0) {
		ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "fail to create mysql socket");
        return NGX_ERROR;
    }
    if(fcntl(sock, F_SETFL, O_NONBLOCK)==-1){
		ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "fail to set mysql socket to noblock");
		goto fail;
	}

    //connect
    do{
        memcpy(temp, mycf->ip.data, mycf->ip.len);
        temp[mycf->ip.len]='\0';
        
        memset(&sin, 0, sizeof(sin));
        sin.sin_family          = PF_INET;
        sin.sin_port            = htons((u_short)mycf->port);
        sin.sin_addr.s_addr     = inet_addr((char*)temp);

        //连接服务器
        ret = connect(sock, (struct sockaddr *)&sin, sizeof(sin));
        if(0!=ret) {
            //ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "fail to connect mysql");

            tv.tv_sec = MYSQL_TIMEOUT;
            tv.tv_usec = 0;

            FD_ZERO(&fsetwrite);
            FD_SET(sock, &fsetwrite);
            ret = select(sock+1,NULL,&fsetwrite,NULL, &tv);
            if (ret<=0) {
                goto fail;
            }
            if(!FD_ISSET(sock, &fsetwrite)) {
                goto fail;
            }

            error = 0;
            len = sizeof(error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&error, &len);
            if (0!=error) {
                goto fail;
            }
        }
    }while(0);

    // Reading Handshake Initialization Packet
    do{
        ret = ngx_mysql_read_packet(sock, temp, sizeof(temp)-1);
        if(ret<=0) {
            goto fail;
        }
        if(0xff==temp[0]){
            error = (int)( (uint32_t)temp[1] | (uint32_t)temp[2]<<8 );
            ngx_str_t errstr;
            errstr.data= temp+3;
            errstr.len=ret-3;
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "fail to connect mysql: code=%d msg=\"%V\"", error, &errstr);
            goto fail;
        }
        // protocol version [1 byte]
        if(temp[0] < 10){
            goto fail;
        }

        // server version [null terminated string]
        // connection id [4 bytes]
        for(index=1; index< ret-2; index++){
            if(temp[index]=='\0') {
                ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "mysql version: %s", (char*)temp+1);
                break;
            }
        }
        pos = index + 1 + 4;
        // first part of the password cipher [8 bytes]
        memcpy(authData, temp+pos, 8);
        authLen=8;
        // (filler) always 0x00 [1 byte]
        pos += 8 + 1;
        // capability flags (lower 2 bytes) [2 bytes]
        flags = (uint32_t)temp[pos] | (uint32_t)(temp[pos+1]<<8);
        //check clientProtocol41
        if((flags & clientProtocol41) == 0){
            goto fail;
        }
        pos+=2;

        if(ret>pos){
            // character set [1 byte]
            // status flags [2 bytes]
            // capability flags (upper 2 bytes) [2 bytes]
            // length of auth-plugin-data [1 byte]
            // reserved (all [00]) [10 bytes]
            pos += 1 + 2 + 2 + 1 + 10;
            memcpy(authData+8, temp+pos, 12);
            authLen+=12;
            pos += 13;

            // EOF if version (>= 5.5.7 and < 5.5.10) or (>= 5.6.0 and < 5.6.2)
            // \NUL otherwise
            for(index=pos; index<ret; index++) {
                if(temp[index]=='\0'){
                    break;
                }
            }
            if(index<ret){
                    strcpy(plugin, (char*)temp+pos);
            }else{
                memcpy(plugin, (char*)temp+pos, ret-pos);
                plugin[ret-pos]='\0';
            }
            if(plugin[0]=='\0'){
                strcpy(plugin, "mysql_native_password");
            }
        }
    }while(0);

    // Send Client Authentication Packet
    do{
        u_char *respBuf;
        int pktLen=0;
        unsigned char authResp[256];
        int authRespLen=0;
        u_char authSizeMark[9];
        int markSize=0;

        if(memcmp(plugin, "caching_sha2_password", 22)==0){
            // XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))
            unsigned char hash[SHA256_DIGEST_LENGTH];
            unsigned char hash2[SHA256_DIGEST_LENGTH+64];

            //SHA256(SHA256(password))
            ngx_mysql_sha256(hash, mycf->pwd.data, mycf->pwd.len);
            ngx_mysql_sha256(hash2, hash, SHA256_DIGEST_LENGTH);

            //SHA256(SHA256(SHA256(password)), scramble)
            memcpy(hash2+SHA256_DIGEST_LENGTH, authData, authLen);
            ngx_mysql_sha256(hash, hash2, SHA256_DIGEST_LENGTH + authLen);

            //SHA256(password)
            ngx_mysql_sha256(hash2, mycf->pwd.data, mycf->pwd.len);

            //XOR
            for(index=0; index<SHA256_DIGEST_LENGTH; index++) {
                authResp[index] = hash2[index] ^ hash[index];
            }
            authRespLen=SHA256_DIGEST_LENGTH;
        }else if(memcmp(plugin, "sha256_password", 16)==0){

        }else if(memcmp(plugin, "mysql_native_password", 22)==0){
            unsigned char hash[SHA_DIGEST_LENGTH];
            unsigned char hash2[SHA_DIGEST_LENGTH+64];

            // stage1Hash = SHA1(password)
            // scrambleHash = SHA1(scramble + SHA1(stage1Hash))
            memcpy(hash2, authData, 20);
            ngx_mysql_sha1(hash2 + 20, mycf->pwd.data, mycf->pwd.len);
            ngx_mysql_sha1(hash, hash2, 20 + SHA_DIGEST_LENGTH);

            // stage1Hash = SHA1(password)
            ngx_mysql_sha1(hash2, mycf->pwd.data, mycf->pwd.len);

            // token = scrambleHash XOR stage1Hash
            for(index=0; index<SHA_DIGEST_LENGTH; index++) {
                authResp[index] = hash2[index] ^ hash[index];
            }
            authRespLen=SHA_DIGEST_LENGTH;
        }else{
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "unknown auth plugin:%s", plugin);
            goto fail;
        }

        flags = clientProtocol41 |
            clientSecureConn |
            clientLongPassword |
            clientTransactions |
            clientLocalFiles |
            clientPluginAuth |
            clientMultiResults |
            (flags & clientLongFlag);

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
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "authRespLen is too big");
            goto fail;
        }
        if(markSize>1) {
		    // if the length can not be written in 1 byte, it must be written as a
		    // length encoded integer
		    flags |= clientPluginAuthLenEncClientData;
        }

        pktLen = 4 + 4 + 1 + 23 + mycf->user.len + 1 + markSize + authRespLen + 21 + 1;

        // To specify a db name
		flags |= clientConnectWithDB;
		pktLen += mycf->dbName.len + 1;

        // Calculate packet length and get buffer with that size
        respBuf=(u_char*)malloc(pktLen+4);
        // ClientFlags [32 bit]
        respBuf[4] = (u_char)flags;
        respBuf[5] = (u_char)(flags >> 8);
        respBuf[6] = (u_char)(flags >> 16);
        respBuf[7] = (u_char)(flags >> 24);
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

        strcpy((char*)respBuf+pos, plugin);
        pos+=strlen(plugin);

        // Send Auth packet
        if(ngx_mysql_write_packet(sock, respBuf, pktLen+4) != NGX_OK) {
            return NGX_ERROR;
        }

    }while(0);

    // Handle response to auth packet, switch methods if possible
    do{
        ret = ngx_mysql_read_packet(sock, temp, sizeof(temp)-1);
        if(ret<=0) {
            goto fail;
        }
        if(0==temp[0]){ //ok package

        } else if(255==temp[0]) { //err pakcage
            // Error Number [16 bit uint]
	        //errno := binary.LittleEndian.Uint16(data[1:3])
            error = (int)( (uint32_t)temp[1] | (uint32_t)temp[2]<<8 );

            pos=3;
            // SQL State [optional: # + 5bytes string]
            if(temp[3] == 0x23) {
                //sqlstate := string(data[4 : 4+5])
                pos = 9;
            }

            ngx_str_t errstr;
            errstr.data= temp+pos;
            errstr.len=ret-pos;
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "fail to auth mysql: code=%d msg=\"%V\"", error, &errstr);
            goto fail;
        }

    }while(0);
    failed = 0;

fail:
    close(sock);
    if(failed) {
		ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "fail to connect mysql");
        return NGX_ERROR;
    }
    return NGX_OK;
}


ngx_int_t
ngx_mysql_write_packet(int sock, u_char *data, int len)
{
    int         ret;
    int         pktLen = len - 4;

    data[0] = (u_char)pktLen;
    data[1] = (u_char)(pktLen >> 8);
    data[2] = (u_char)(pktLen >> 16);
    data[3] = ngx_mysql_connection.sequence;

    ret = send(sock, data, len, 0);
    if(ret!=len) {
        return NGX_ERROR;
    }

    ngx_mysql_connection.sequence++;
    return NGX_OK;
}


ngx_int_t
ngx_mysql_read_packet(int sock, u_char *buf, int cap)
{
    int         pktLen;
    int         ret;
    int         got;

    // read packet header
    if(4 != ngx_mysql_read(sock, buf, 4)) {
        return NGX_ERROR;
    }
    // packet length [24 bit]
	pktLen = (int)( (uint32_t)(buf[0]) | ((uint32_t)(buf[1]))<<8 | ((uint32_t)(buf[2]))<<16);
    // check packet sync [8 bit]
    if(buf[3] != ngx_mysql_connection.sequence) {
        return NGX_ERROR;
    }
    ngx_mysql_connection.sequence++;

    if(0==pktLen) {
        return 4;
    }
    // read packet body [pktLen bytes]
    got = 0;
    for(; got < pktLen;){
        ret = ngx_mysql_read(sock, buf + got, cap - got);
        if(ret<=0){
            return NGX_ERROR;
        }
        got += ret;
    }

    return got;
}


ngx_int_t
ngx_mysql_read(int sock, u_char *buf, int cap)
{
	int             ret;
	fd_set          fsetread;
	struct timeval  tv;

    tv.tv_sec = MYSQL_TIMEOUT;
    tv.tv_usec = 0;

    FD_ZERO(&fsetread);
    FD_SET(sock, &fsetread);
    ret=select(sock+1, &fsetread, NULL, NULL, &tv);

    if(ret<=0) {
        return NGX_ERROR;
    }
    ret = recv(sock, (char*)buf, cap, 0); 

    return (ngx_int_t)ret;
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
