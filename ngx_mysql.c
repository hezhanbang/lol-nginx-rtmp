
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
ngx_int_t ngx_mysql_read_packet(int sock, u_char *buf, int cap);
ngx_int_t ngx_mysql_read(int sock, u_char *buf, int cap);


#define MYSQL_TIMEOUT (3)


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

    //database
    p = ngx_pstrdup(cf->cycle->pool, value+5);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }
    mycf->database.data = p;
    mycf->database.len= value[5].len;

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
    int                 index;
    int                 pos = 0;
    u_char              authData[8];

    mycf = (ngx_mysql_conf_t*)cycle->conf_ctx[ngx_mysql_module.index];
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, 
        "hebang do ngx_mysql_connect [ip=%V port=%d user=%V pwd=%V database=%V",
        &mycf->ip,
        mycf->port,
        &mycf->user,
        &mycf->pwd,
        &mycf->database
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

    // Reading Handshake Initialization Packet
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

fail:
    close(sock);
    if(failed) {
		ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "fail to connect mysql");
        return NGX_ERROR;
    }
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