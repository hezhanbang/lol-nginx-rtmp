#ifndef _NGX_MYSQL_H_INCLUDED_
#define _NGX_MYSQL_H_INCLUDED_


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
    ngx_str_t dbName;
} ngx_mysql_conf_t;

typedef struct {

    ngx_int_t           connected;
    int                 sock;
    uint8_t             sequence;
    ngx_pool_t         *pool;
    ngx_int_t           timeout;
    ngx_chain_t        *in;
    ngx_chain_t        *out;

    //handshake
    uint32_t            flags;
    u_char              authData[8+12];
    int                 authLen;
    char                plugin[32];
} ngx_mysql_ctx_t;

ngx_int_t ngx_mysql_query(char *sql);

#endif /* _NGX_MYSQL_H_INCLUDED_ */
