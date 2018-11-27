
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
    return mycf;
}


static ngx_int_t
ngx_mysql_init_process(ngx_cycle_t *cycle)
{
    //debug only
    ngx_mysql_query(cycle, "");
    return NGX_OK;
}

ngx_int_t ngx_mysql_connect(ngx_cycle_t *cycle, ngx_mysql_conf_t *mycf)
{
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "hebang do ngx_mysql_connect");
    return NGX_OK;
}

ngx_int_t
ngx_mysql_query(ngx_cycle_t *cycle, char *sql)
{
    ngx_mysql_conf_t *mycf = (ngx_mysql_conf_t*)cycle->conf_ctx[ngx_mysql_module.index];

    if(0 == mycf->connected) {
        if(NGX_OK == ngx_mysql_connect(cycle, mycf)){
            mycf->connected = 1;
        }
    }

    return NGX_OK;
}