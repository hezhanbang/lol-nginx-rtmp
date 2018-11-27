#ifndef _NGX_RTMP_H_INCLUDED_
#define _NGX_RTMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <nginx.h>


typedef struct {
    ngx_str_t ip;
    ngx_int_t port;
    ngx_str_t user;
    ngx_str_t pwd;
    ngx_str_t database;
} ngx_mysql_conf_t;


#endif /* _NGX_RTMP_H_INCLUDED_ */
