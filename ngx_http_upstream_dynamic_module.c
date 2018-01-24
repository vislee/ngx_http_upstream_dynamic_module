// Copyright (C) 2017-2018 liwq

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
} ngx_http_upstream_dynamic_srv_conf_t;


typedef struct {
    ngx_http_upstream_srv_conf_t     *uscf;
    in_port_t                         port;
} ngx_http_upstream_resolover_ctx_t;


typedef struct {
    ngx_uint_t    status;
    ngx_str_t     code;
    ngx_str_t     text;
} ngx_http_upstream_resp_error_t;


static char *ngx_http_upstream_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_server_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_upstream_dynamic_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_init_resolver(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_init_resolver_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);


static ngx_command_t  ngx_http_upstream_dynamic_commands[] = {

    { ngx_string("server_resolver"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_server_resolver,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("http_upstream_conf"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_dynamic_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_upstream_dynamic_create_conf,  /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};



ngx_module_t  ngx_http_upstream_dynamic_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_dynamic_module_ctx,     /* module context */
    ngx_http_upstream_dynamic_commands,        /* module directives */
    NGX_HTTP_MODULE,                           /* module type */
    NULL,                                      /* init master */
    NULL,                                      /* init module */
    NULL,                                      /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    NULL,                                      /* exit process */
    NULL,                                      /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_upstream_dynamic_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_dynamic_srv_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_upstream_dynamic_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_upstream_server_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_dynamic_srv_conf_t   *dscf = conf;
    ngx_http_upstream_srv_conf_t           *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (NULL == uscf->shm_zone) {
        return "must reside in the shared memory";
    }

    dscf->init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream:
                               ngx_http_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_http_upstream_init_resolver;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upstream_init_resolver(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t                               res;
    ngx_http_upstream_dynamic_srv_conf_t   *dscf;

    dscf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_dynamic_module);
    if (dscf == NULL) {
        return NGX_ERROR;
    }

    res = dscf->init_upstream(cf, us);
    if (res != NGX_OK) {
        return res;
    }

    dscf->init = us->peer.init;
    us->peer.init = ngx_http_upstream_init_resolver_peer;

    return NGX_OK;
}


static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_zone_copy_peer(ngx_http_upstream_rr_peers_t *peers, ngx_str_t *server,
    ngx_str_t *host, in_port_t port, struct sockaddr *sockaddr, socklen_t socklen)
{
    size_t                        plen;
    ngx_slab_pool_t              *pool;
    ngx_http_upstream_rr_peer_t  *dst;

    pool = peers->shpool;
    if (pool == NULL) return NULL;

    ngx_shmtx_lock(&pool->mutex);
    dst = ngx_slab_calloc_locked(pool, sizeof(ngx_http_upstream_rr_peer_t));
    if (dst == NULL) {
        ngx_shmtx_unlock(&pool->mutex);
        return NULL;
    }

    dst->socklen  = socklen;
    dst->sockaddr = NULL;
    dst->name.data = NULL;
    dst->server.data = NULL;

    if (server == NULL) {
        if (port > 1 && port < 10) {
            plen = 1;
        } else if (port < 100) {
            plen = 2;
        } else if (port < 1000) {
            plen = 3;
        } else if (port < 10000) {
            plen = 4;
        } else {
            plen = 5;
        }
        dst->server.len = host->len + 1 + plen;

    } else {
        dst->server.len = server->len;
    }

    dst->sockaddr = ngx_slab_calloc_locked(pool, sizeof(ngx_sockaddr_t));
    if (dst->sockaddr == NULL) {
        goto failed;
    }

    dst->name.data = ngx_slab_calloc_locked(pool, NGX_SOCKADDR_STRLEN);
    if (dst->name.data == NULL) {
        goto failed;
    }


    ngx_memcpy(dst->sockaddr, sockaddr, socklen);
    ngx_inet_set_port(dst->sockaddr, port);
    dst->name.len = ngx_sock_ntop(dst->sockaddr, socklen, dst->name.data, NGX_SOCKADDR_STRLEN, 1);

    dst->server.data = ngx_slab_alloc_locked(pool, dst->server.len);
    if (dst->server.data == NULL) {
        goto failed;
    }

    if (server == NULL) {
        ngx_memcpy(dst->server.data, host->data, host->len);
        ngx_sprintf(dst->server.data + host->len, ":%d", port);
    } else {
        ngx_memcpy(dst->server.data, server->data, server->len);
    }

    ngx_shmtx_unlock(&pool->mutex);
    return dst;

failed:

    if (dst->server.data) {
        ngx_slab_free_locked(pool, dst->server.data);
    }

    if (dst->name.data) {
        ngx_slab_free_locked(pool, dst->name.data);
    }

    if (dst->sockaddr) {
        ngx_slab_free_locked(pool, dst->sockaddr);
    }

    ngx_slab_free_locked(pool, dst);
    ngx_shmtx_unlock(&pool->mutex);

    return NULL;
}


static void
ngx_http_upstream_zone_free_peer(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peer_t *dst)
{
    ngx_slab_pool_t              *pool;

    if (dst == NULL) return;

    pool = peers->shpool;
    if (pool == NULL) return;

    ngx_shmtx_lock(&pool->mutex);

    if (dst->server.data) {
        ngx_slab_free_locked(pool, dst->server.data);
    }

    if (dst->name.data) {
        ngx_slab_free_locked(pool, dst->name.data);
    }

    if (dst->sockaddr) {
        ngx_slab_free_locked(pool, dst->sockaddr);
    }

    ngx_slab_free_locked(pool, dst);
    ngx_shmtx_unlock(&pool->mutex);

    return;
}


static void
ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx) {
    u_char                             *p;
    ngx_uint_t                          i;
    in_port_t                           port;
    ngx_str_t                           name;
    ngx_http_upstream_resolover_ctx_t  *urctx = ctx->data;
    ngx_http_upstream_rr_peers_t       *peers;
    ngx_http_upstream_rr_peer_t        *peer, *nxt, **ups_nxt;
    time_t                              fail_timeout;
    ngx_int_t                           weight, max_fails;
    struct sockaddr_in                 *sin, *peer_sin;

    #if (nginx_version >= 1011005)
    ngx_int_t                           max_conns;
    #endif

    peers = urctx->uscf->peer.data;
    port  = urctx->port;
    name  = ctx->name;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
        "resolver handler name: \"%V\" state: %i", &name, ctx->state);

    if (NGX_AGAIN == ctx->state) {
        return;
    }

    if (ctx->state) {
        ngx_shmtx_lock(&peers->shpool->mutex);
        ngx_slab_free_locked(peers->shpool, name.data);
        ngx_shmtx_unlock(&peers->shpool->mutex);

        ngx_free(urctx);
        ctx->data = NULL;
        ngx_resolve_name_done(ctx);

        return;
    }

#if (NGX_DEBUG)
    {
    u_char      text[NGX_SOCKADDR_STRLEN];
    ngx_str_t   addr;
    ngx_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = ngx_sock_ntop(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                                 text, NGX_SOCKADDR_STRLEN, 0);
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                       "resolver handler name: \"%V\" was resolver to: %V", &name, &addr);
    }
    }
#endif

    fail_timeout = 10;
    weight = 1;
    #if (nginx_version >= 1011005)
    max_conns = 0;
    #endif
    max_fails = 1;

    ngx_http_upstream_rr_peers_wlock(peers);
    for (peer = peers->peer, ups_nxt = &peers->peer; peer; peer = nxt) {

        nxt = peer->next;
        p = ngx_strlchr(peer->server.data, peer->server.data + peer->server.len, ':');
        if ((p != NULL && (size_t)(p - peer->server.data) != name.len) ||
            (p == NULL && peer->server.len != name.len) ||
            ngx_strncmp(peer->server.data, name.data, name.len) != 0)
        {
            ups_nxt = &peer->next;
            continue;
        }

        fail_timeout = peer->fail_timeout;
        #if (nginx_version >= 1011005)
        max_conns    = peer->max_conns;
        #endif
        max_fails    = peer->max_fails;
        weight       = peer->weight;

        // TODO:
        peer_sin = (struct sockaddr_in *)peer->sockaddr;
        for (i = 0; i < ctx->naddrs; ++i) {
            sin = (struct sockaddr_in *)ctx->addrs[i].sockaddr;
            // The IP does not change. keep this peer.
            if (peer_sin->sin_addr.s_addr == sin->sin_addr.s_addr) {
                ups_nxt = &peer->next;
                goto skip_del;
            }
        }

        // The IP is not exists, down or free this peer.
        if (peer->conns > 0) {
            ups_nxt = &peer->next;
            peer->down |= 0x2;
            continue;
        }

        peers->number--;
        peers->total_weight -= weight;
        *ups_nxt = nxt;
        ngx_http_upstream_zone_free_peer(peers, peer);

    skip_del:
        continue;
    }

    for (i = 0; i < ctx->naddrs; ++i) {
        // TODO:
        sin = (struct sockaddr_in *)ctx->addrs[i].sockaddr;
        for (peer = peers->peer; peer; peer = peer->next) {
            peer_sin = (struct sockaddr_in *)peer->sockaddr;
            // The IP have exists. update the expire.
            if (peer_sin->sin_addr.s_addr == sin->sin_addr.s_addr) {
                #if (NGX_COMPAT)
                peer->spare[0] = ctx->valid;
                #endif
                goto skip_add;
            }
        }

        peer = ngx_http_upstream_zone_copy_peer(peers, NULL, &name, port, ctx->addrs[i].sockaddr, ctx->addrs[i].socklen);
        if (peer == NULL) {
            continue;
        }
        peer->fail_timeout = fail_timeout;
        #if (nginx_version >= 1011005)
        peer->max_conns = max_conns;
        #endif
        peer->max_fails = max_fails;
        peer->weight = weight;
        peer->effective_weight = weight;
        peer->current_weight   = 0;
        #if (NGX_COMPAT)
        peer->spare[0] = ctx->valid;
        #endif

        peer->next = peers->peer;
        peers->peer = peer;
        peers->number++;
        peers->total_weight += weight;

    skip_add:
        continue;
    }

    peers->single = (peers->number == 1);

    ngx_shmtx_lock(&peers->shpool->mutex);
    ngx_slab_free_locked(peers->shpool, name.data);
    ngx_shmtx_unlock(&peers->shpool->mutex);

    ngx_http_upstream_rr_peers_unlock(peers);

    ngx_free(urctx);
    ctx->data = NULL;
    ngx_resolve_name_done(ctx);

    return;
}


static ngx_int_t
ngx_http_upstream_init_resolver_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    time_t                                     expire;
    ngx_int_t                                  res;
    ngx_str_t                                  host;
    ngx_url_t                                  url;
    ngx_resolver_ctx_t                        *ctx, temp;
    ngx_http_upstream_rr_peers_t              *peers;
    ngx_http_upstream_rr_peer_t               *peer, *nxt, **ups_nxt;;
    ngx_http_upstream_dynamic_srv_conf_t      *dscf;
    ngx_http_core_loc_conf_t                  *clcf;
    ngx_http_upstream_resolover_ctx_t         *urctx;

    dscf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_dynamic_module);
    if (NULL == dscf) {
        return NGX_ERROR;
    }

    res = dscf->init(r, us);
    if (res != NGX_OK) {
        return res;
    }

    // equivalent to r->upstream->peer.data->peers;
    peers = us->peer.data;
    ngx_http_upstream_rr_peers_wlock(peers);
    for (peer = peers->peer, ups_nxt = &peers->peer; peer != NULL; peer = nxt) {
        nxt = peer->next;

        if (peer->down & 0x2 && peer->conns == 0) {
            // Free the down peer.
            *ups_nxt = nxt;
            peers->number--;
            peers->total_weight -= peer->weight;
            ngx_http_upstream_zone_free_peer(peers, peer);
            continue;
        }

        ngx_memzero(&url, sizeof(ngx_url_t));
        url.url.len = peer->server.len;
        url.url.data = peer->server.data;
        url.default_port = 80;
        url.no_resolve = 1;

        if (ngx_parse_url(r->pool, &url) != NGX_OK || url.host.len == 0 || url.naddrs > 0) {
            goto next;
        }

        expire = ngx_time();
        #if (NGX_COMPAT)
        expire = peer->spare[0]? peer->spare[0]: 1;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "compat check resolver \"%V\" expire: %l", &url.host, expire);
        #endif

        if (
        #if (NGX_DEBUG)
            1 ||
        #endif
            expire < ngx_time()
            || peer->fails > peer->max_fails
            )
        {
            break;
        }

        next:
        ups_nxt = &peer->next;
        // not resolver this peer
        url.naddrs = 1;
    }

    if (url.naddrs != 0) {
        // no need resolver domain
        ngx_http_upstream_rr_peers_unlock(peers);
        return NGX_OK;
    }

    ngx_shmtx_lock(&peers->shpool->mutex);
    host.data = ngx_slab_alloc_locked(peers->shpool, url.host.len);
    ngx_shmtx_unlock(&peers->shpool->mutex);
    if (host.data == NULL) {
        ngx_http_upstream_rr_peers_unlock(peers);
        return NGX_OK;
    }
    ngx_memcpy(host.data, url.host.data, url.host.len);
    host.len = url.host.len;

    // TODO:
    // 10s retry
    #if (NGX_COMPAT)
    ngx_http_upstream_rr_peer_lock(peers, peer);
    peer->spare[0] += 10;
    ngx_http_upstream_rr_peer_unlock(peers, peer);
    #endif

    ngx_http_upstream_rr_peers_unlock(peers);

    urctx = NULL;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL) {
        goto failed;
    }

    urctx = ngx_alloc(sizeof(ngx_http_upstream_resolover_ctx_t), clcf->resolver->log);
    if (urctx == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "alloc ctx null. size: %uz", sizeof(ngx_http_upstream_resolover_ctx_t));
        goto failed;
    }

    temp.name = host;
    ctx = ngx_resolve_start(clcf->resolver, &temp);
    if (ctx == NULL) {
        return NGX_OK;
    }
    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "no resolver defined to resolve %V", &host);
        goto failed;
    }

    urctx->port = url.port;
    urctx->uscf = us;

    ctx->data = urctx;
    ctx->name = host;
    ctx->handler = ngx_http_upstream_resolve_handler;
    ctx->timeout = clcf->resolver_timeout;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "start resolver \"%V\"", &host);

    if (ngx_resolve_name(ctx) != NGX_OK) {
        goto failed;
    }

    return NGX_OK;


failed:

    ngx_shmtx_lock(&peers->shpool->mutex);
    ngx_slab_free_locked(peers->shpool, host.data);
    ngx_shmtx_unlock(&peers->shpool->mutex);
    if (NULL != urctx) {
        ngx_free(urctx);
    }

    return NGX_OK;
}


/*
 * http_upstreams
 */

static ngx_str_t UpstreamNotFound   = ngx_string("UpstreamNotFound");
static ngx_str_t UpstreamStatic     = ngx_string("UpstreamStatic");
static ngx_str_t MethodDisabled     = ngx_string("MethodDisabled");
static ngx_str_t CmdFormatError     = ngx_string("CmdFormatError");
static ngx_str_t ArgsFormatError    = ngx_string("ArgsFormatError");
static ngx_str_t UrlFormatError     = ngx_string("UrlFormatError");
static ngx_str_t UpstreamBadAddress = ngx_string("UpstreamBadAddress");
static ngx_str_t InternalError      = ngx_string("InternalError");



static size_t
ngx_http_upstream_peers_dump_json(ngx_http_request_t *r, ngx_http_upstream_rr_peers_t *peers, ngx_buf_t **buf)
{
    ngx_buf_t                      *b;
    ngx_int_t                       max_conns;
    u_char                          flag[64];
    size_t                          len, flen, size;
    ngx_http_upstream_rr_peer_t    *peer;
    ngx_http_upstream_rr_peers_t   *backup;

    ngx_http_upstream_rr_peers_rlock(peers);
    backup = peers->next;

    len = sizeof("{\"\" : {\"peers\" : [  ]}}") - 1 + peers->name->len;
    for (peer = peers->peer; peer != NULL; peer = peer->next) {
        ngx_memset(flag, 0x00, 64);
        max_conns = 0;
        #if (nginx_version >= 1011005)
        max_conns =  peer->max_conns;
        #endif
        flen = ngx_snprintf(flag, 64, "%d%d%d%d%d%d",
            peer->weight, max_conns, peer->conns, peer->fails, peer->max_fails, peer->down) - flag;

        len += sizeof("{\"server\" : \"\", \"name\" : \"\", \"weight\" : , \"max_conns\" : , \"connections\" : , \
\"fails\" : , \"max_fails\" : , \"down\" : , \"backup\" : false},") - 1 +
                      peer->server.len + peer->name.len + flen;
    }

    if (backup != NULL) {
        for (peer = backup->peer; peer != NULL; peer = peer->next) {
            ngx_memset(flag, 0x00, 64);
            max_conns = 0;
            #if (nginx_version >= 1011005)
            max_conns =  peer->max_conns;
            #endif
            flen = ngx_snprintf(flag, 64, "%d%d%d%d%d%d",
                peer->weight, max_conns, peer->conns, peer->fails, peer->max_fails, peer->down) - flag;

            len += sizeof("{\"server\" : \"\", \"name\" : \"\", \"weight\" : , \"max_conns\" : , \"connections\" : , \
\"fails\" : , \"max_fails\" : , \"down\" : , \"backup\" : true},") - 1 +
                          peer->server.len + peer->name.len + flen;
        }
    }
    len--;

    b = ngx_create_temp_buf(r->pool, len);
    if (NULL == b) {
        ngx_http_upstream_rr_peers_unlock(peers);
        return 0;
    }

    size = b->end - b->last;
    b->last = ngx_snprintf(b->last, size, "{\"%V\" : {\"peers\" : [ ", peers->name);
    for (peer = peers->peer; peer != NULL; peer = peer->next) {
        max_conns = 0;
        #if (nginx_version >= 1011005)
        max_conns =  peer->max_conns;
        #endif

        size = b->end - b->last;
        b->last = ngx_snprintf(b->last, size,
            "{\"server\" : \"%V\", \"name\" : \"%V\", \"weight\" : %d, \"max_conns\" : %d, \"connections\" : %d, \
\"fails\" : %d, \"max_fails\" : %d, \"down\" : %d, \"backup\" : false},",
            &peer->server, &peer->name, peer->weight, max_conns, peer->conns, peer->fails, peer->max_fails, peer->down);
    }
    if (backup != NULL) {
        for (peer = backup->peer; peer != NULL; peer = peer->next) {
            max_conns = 0;
            #if (nginx_version >= 1011005)
            max_conns =  peer->max_conns;
            #endif
            size = b->end - b->last;
            b->last = ngx_snprintf(b->last, size,
                "{\"server\" : \"%V\", \"name\" : \"%V\", \"weight\" : %d, \"max_conns\" : %d, \"connections\" : %d, \
\"fails\" : %d, \"max_fails\" : %d, \"down\" : %d, \"backup\" : true},",
                &peer->server, &peer->name, peer->weight, max_conns, peer->conns, peer->fails, peer->max_fails, peer->down);
        }
    }
    b->last--;
    size = b->end - b->last;
    b->last = ngx_snprintf(b->last, size, " ]}}");

    ngx_http_upstream_rr_peers_unlock(peers);

    *buf = b;

    return len;
}


static ngx_int_t
ngx_http_upstream_peer_add(ngx_http_request_t *r, ngx_http_upstream_rr_peers_t *peers,
                           ngx_str_t *server, ngx_str_t *ip,
                           ngx_int_t weight, ngx_int_t max_conns, ngx_int_t max_fails, ngx_int_t fail_timeout,
                           ngx_http_upstream_resp_error_t *err)
{
    ngx_url_t                       url;
    ngx_http_upstream_rr_peer_t    *peer;

    ngx_http_upstream_rr_peers_wlock(peers);
    for (peer = peers->peer; peer != NULL; peer = peer->next) {
        if (peer->server.len == server->len && ngx_strncmp(peer->server.data, server->data, server->len) == 0 &&
            peer->name.len == ip->len && ngx_strncmp(peer->name.data, ip->data, ip->len) == 0) {
            if (peer->down) {
                peer->down = 0;
            } else {
                if (weight > 0) {
                    peers->total_weight += weight - peer->weight;
                    peer->weight = weight;
                }

                #if (nginx_version >= 1011005)
                if (max_conns > 0) {
                    peer->max_conns = max_conns;
                }
                #endif

                if (max_fails > 0) {
                    peer->max_fails = max_fails;
                }
                if (fail_timeout > 0) {
                    peer->fail_timeout = fail_timeout;
                }
            }
            ngx_http_upstream_rr_peers_unlock(peers);
            return NGX_OK;
        }
    }
    ngx_http_upstream_rr_peers_unlock(peers);

    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url.len = ip->len;
    url.url.data = ip->data;
    url.default_port = 80;
    url.no_resolve = 1;
    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        err->status = NGX_HTTP_BAD_REQUEST;
        err->code   = UpstreamBadAddress;
        err->text   = UpstreamBadAddress;
        return NGX_ERROR;
    }

    if (url.naddrs == 0) {
        err->status = NGX_HTTP_BAD_REQUEST;
        err->code   = UpstreamBadAddress;
        err->text   = UpstreamBadAddress;
        return NGX_ERROR;
    }

    // todo
    peer = ngx_http_upstream_zone_copy_peer(peers, server, &url.host, url.port, url.addrs[0].sockaddr, url.addrs[0].socklen);
    if (peer == NULL) {
        err->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        err->code   = InternalError;
        err->text   = InternalError;
        return NGX_ERROR;
    }

    ngx_http_upstream_rr_peers_wlock(peers);
    ngx_http_upstream_rr_peer_lock(peers, peer);
    peer->fail_timeout = fail_timeout;
    peer->weight = weight;

    #if (nginx_version >= 1011005)
    peer->max_conns = max_conns;
    #endif

    peer->max_fails = max_fails;
    peer->next = peers->peer;
    ngx_http_upstream_rr_peer_unlock(peers, peer);

    peers->peer = peer;
    peers->number++;
    peers->total_weight += peer->weight;
    ngx_http_upstream_rr_peers_unlock(peers);

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstreams_peer_down(ngx_http_upstream_rr_peers_t *peers, ngx_str_t *server, ngx_str_t *ip)
{
    ngx_http_upstream_rr_peer_t    *peer;
    ngx_http_upstream_rr_peers_wlock(peers);
    for (peer = peers->peer; peer != NULL; peer = peer->next) {
        if (peer->server.len == server->len && ngx_strncmp(peer->server.data, server->data, server->len) == 0 &&
            peer->name.len == ip->len && ngx_strncmp(peer->name.data, ip->data, ip->len) == 0) {
            ngx_http_upstream_rr_peer_lock(peers, peer);
            peer->down |= 0x4;
            ngx_http_upstream_rr_peer_unlock(peers, peer);
            ngx_http_upstream_rr_peers_unlock(peers);
            return NGX_OK;
        }
    }
    ngx_http_upstream_rr_peers_unlock(peers);

    return NGX_BUSY;
}

/*
 * /xxx/list?ups=ups
 * /xxx/add?ups=ups&ip=xxx.xxx.xxx.xxx
 * /xxx/down?ups=ups&ip=xxx.xxx.xxx.xxx
 */
static ngx_int_t
ngx_http_upstream_conf_handler(ngx_http_request_t *r)
{
    size_t                          len;
    u_char                         *u, *p;
    time_t                          fail_timeout;
    ngx_uint_t                      j;
    ngx_int_t                       i, rc, weight, max_conns, max_fails;
    ngx_str_t                       key, ups, server, ip, w, mc, mf, ft, type;
    ngx_buf_t                      *b;
    ngx_chain_t                     out;
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_rr_peers_t   *peers;
    ngx_http_upstream_resp_error_t  err;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        err.status = NGX_HTTP_NOT_FOUND;
        err.code = UpstreamNotFound;
        err.text = UpstreamNotFound;
        goto failed;
    }

    if (!(r->method & NGX_HTTP_GET)) {
        err.status = NGX_HTTP_NOT_ALLOWED;
        err.code   = MethodDisabled;
        err.text   = MethodDisabled;
        goto failed;
    }

    rc = ngx_http_discard_request_body(r);
    if (NGX_OK != rc) {
        return rc;
    }

    if (r->uri.len == 0 || r->uri.data[0] != '/') {
        err.status = NGX_HTTP_BAD_REQUEST;
        err.code   = UrlFormatError;
        err.text   = UrlFormatError;
        goto failed;
    }

    u = NULL;
    for(i = r->uri.len-2; i >= 0; --i) {
        u = r->uri.data + i;
        if (*u == '/') {
            break;
        }
    }

    ngx_str_null(&key);
    ngx_str_null(&ip);
    ngx_str_null(&server);
    ngx_str_null(&ups);
    ngx_str_null(&w);
    ngx_str_null(&mc);
    ngx_str_null(&mf);
    ngx_str_null(&ft);
    for (j = 0; j < r->args.len; j++) {
        if (r->args.len - j > 4 && ngx_strncmp(r->args.data + j, "ups=", 4) == 0) {

            key.data = r->args.data + j;
            key.len  = 3;
            ups.data = r->args.data + j + 4;
            ups.len  = r->args.len - j - 4;
            j += 3;
        } else if (r->args.len - j > 3 && ngx_strncmp(r->args.data + j, "ip=", 3) == 0) {

            key.data = r->args.data + j;
            key.len  = 2;
            ip.data = r->args.data + j + 3;
            ip.len  = r->args.len - j - 3;
            j += 2;
        } else if (r->args.len - j > 7 && ngx_strncmp(r->args.data + j, "server=", 7) == 0) {

            key.data = r->args.data + j;
            key.len  = 6;
            server.data = r->args.data + j + 7;
            server.len  = r->args.len - j - 7;
            j += 6;
        } else if (r->args.len - j > 5 && ngx_strncmp(r->args.data + j, "weight=", 7) == 0) {

            key.data = r->args.data + j;
            key.len  = 6;
            w.data = r->args.data + j + 7;
            w.len  = r->args.len - j - 7;
            j += 6;
        } else if (r->args.len - j > 10 && ngx_strncmp(r->args.data + j, "max_conns=", 10) == 0) {

            key.data = r->args.data + j;
            key.len  = 9;
            mc.data = r->args.data + j + 10;
            mc.len  = r->args.len - j - 10;
            j += 9;
        } else if (r->args.len - j > 10 && ngx_strncmp(r->args.data + j, "max_fails=", 10) == 0) {

            key.data = r->args.data + j;
            key.len  = 9;
            mf.data = r->args.data + j + 10;
            mf.len  = r->args.len - j - 10;
            j += 9;
        } else if (r->args.len - j > 13 && ngx_strncmp(r->args.data + j, "fail_timeout=", 13) == 0) {

            key.data = r->args.data + j;
            key.len  = 12;
            ft.data = r->args.data + j + 13;
            ft.len  = r->args.len - j - 13;
            j += 12;
        }

        p = &r->args.data[j];
        if (*p == '&') {
            if (ups.data != NULL && 
                key.len == 3 && ngx_strncmp(key.data, "ups", key.len) == 0) {
                ups.len = p - ups.data;
            } else if (ip.data != NULL &&
                key.len == 2 && ngx_strncmp(key.data, "ip", key.len) == 0) {
                ip.len = p - ip.data;
            } else if (server.data != NULL &&
                key.len == 6 && ngx_strncmp(key.data, "server", key.len) == 0) {
                server.len = p - server.data;
            } else if (w.data != NULL &&
                key.len == 6 && ngx_strncmp(key.data, "weight", key.len) == 0) {
                w.len = p - w.data;
            } else if (mc.data != NULL &&
                key.len == 9 && ngx_strncmp(key.data, "max_conns", key.len) == 0) {
                mc.len = p - mc.data;
            } else if (mf.data != NULL &&
                key.len == 9 && ngx_strncmp(key.data, "max_fails", key.len) == 0) {
                mf.len = p - mf.data;
            } else if (ft.data != NULL &&
                key.len == 12 && ngx_strncmp(key.data, "fail_timeout", key.len) == 0) {
                ft.len = p - ft.data;
            }
        }
    }

    if (ups.len == 0) {
        err.status = NGX_HTTP_BAD_REQUEST;
        err.code   = ArgsFormatError;
        err.text   = ArgsFormatError;
        goto failed;
    }

    weight = 1;
    if (w.len > 0) {
        weight = ngx_atoi(w.data, w.len);
        if (weight == NGX_ERROR || weight == 0) {
            err.status = NGX_HTTP_BAD_REQUEST;
            err.code   = ArgsFormatError;
            err.text   = ArgsFormatError;
            goto failed;
        }
    }

    max_conns = 0;
    if (mc.len > 0) {
        max_conns = ngx_atoi(mc.data, mc.len);
        if (weight == NGX_ERROR || weight == 0) {
            err.status = NGX_HTTP_BAD_REQUEST;
            err.code   = ArgsFormatError;
            err.text   = ArgsFormatError;
            goto failed;
        }
    }

    max_fails = 1;
    if (mf.len > 0) {
        max_fails = ngx_atoi(mf.data, mf.len);
        if (weight == NGX_ERROR || weight == 0) {
            err.status = NGX_HTTP_BAD_REQUEST;
            err.code   = ArgsFormatError;
            err.text   = ArgsFormatError;
            goto failed;
        }
    }

    fail_timeout = 10;
    if (ft.len > 0) {
        fail_timeout = ngx_parse_time(&ft, 1);
        if (fail_timeout == (time_t) NGX_ERROR) {
            err.status = NGX_HTTP_BAD_REQUEST;
            err.code   = ArgsFormatError;
            err.text   = ArgsFormatError;
            goto failed;
        }
    }

    if (server.len == 0) {
        server = ip;
    }

    ngx_log_debug7(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "upstream resolver handler cmd: ups:%V, server:%V, ip:%V, \
weight:%d, max_conns:%d, max_fails=%d, fail_timeout=%d",
                    &ups, &server, &ip, weight, max_conns, max_fails, fail_timeout);

    peers = NULL;
    uscfp = umcf->upstreams.elts;
    for (j = 0; j < umcf->upstreams.nelts; j++) {
        uscf = uscfp[j];

        peers = uscf->peer.data;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "upstream server name: %V", peers->name);
        if (peers->name->len != ups.len || ngx_strncmp(peers->name->data, ups.data, ups.len) != 0) {
            continue;
        }

        if (uscf->shm_zone == NULL) {
            err.status = NGX_HTTP_NOT_FOUND;
            err.code = UpstreamStatic;
            err.text = UpstreamStatic;
            goto failed;
        }

        break;
    }

    if (peers->name->len != ups.len || ngx_strncmp(peers->name->data, ups.data, ups.len) != 0) {
        err.status = NGX_HTTP_NOT_FOUND;
        err.code = UpstreamNotFound;
        err.text = UpstreamNotFound;
        goto failed;
    }


    len = 0;
    b = NULL;

    if (ngx_memcmp(u, "/list", 5) == 0) {
        len = ngx_http_upstream_peers_dump_json(r, peers, &b);

    } else if (ngx_memcmp(u, "/add", 4) == 0) {
        if (ngx_http_upstream_peer_add(r, peers, &server, &ip,
                weight, max_conns, max_fails, fail_timeout, &err) != NGX_OK)
        {
            goto failed;
        }
        len = sizeof("{\"path\" : \"\", \"error\" : {\"code\" : \"200\"}}") - 1 + r->uri.len;
        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        b->last = ngx_snprintf(b->last, len, "{\"path\" : \"%V\", \"error\" : {\"code\" : \"200\"}}", &r->uri);

    } else if (ngx_memcmp(u, "/down", 5) == 0) {
        if (ngx_http_upstreams_peer_down(peers, &server, &ip) != NGX_OK) {
            err.status = NGX_HTTP_NOT_FOUND;
            err.code   = UpstreamNotFound;
            err.text   = UpstreamNotFound;
            goto failed;
        }
        len = sizeof("{\"path\" : \"\", \"error\" : {\"code\" : \"200\"}}") - 1 + r->uri.len;
        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        b->last = ngx_snprintf(b->last, len, "{\"path\" : \"%V\", \"error\" : {\"code\" : \"200\"}}", &r->uri);

    } else {
        err.status = NGX_HTTP_BAD_REQUEST;
        err.code = CmdFormatError;
        err.text = CmdFormatError;
        goto failed;
    }


    if (b == NULL || len == 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_str_set(&type, "application/json");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (NGX_ERROR == rc || NGX_OK < rc || r->header_only) {
        return rc;
    }

    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);


failed:
    len = sizeof("{\"path\" : \"\", \"error\" : {\"status\" : \"\", \"text\" : \"\", \"code\" : \"\"}}") - 1 +
                r->uri.len + 3 + err.text.len + err.code.len;
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->last = ngx_snprintf(b->last, len, "{\"path\" : \"%V\", \"error\" : {\"status\" : \"%d\", \"text\" : \"%V\", \"code\" : \"%V\"}}",
                           &r->uri, err.status, &err.text, &err.code);

    ngx_str_set(&type, "application/json");
    r->headers_out.status = err.status;
    r->headers_out.content_length_n = len;
    r->headers_out.content_type = type;


    rc = ngx_http_send_header(r);
    if (NGX_ERROR == rc || NGX_OK < rc || r->header_only) {
        return rc;
    }

    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_upstream_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upstream_conf_handler;

    return NGX_CONF_OK;
}
