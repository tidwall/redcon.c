// Copyright 2020 Joshua J Baker. All rights reserved.
// Documentation at https://github.com/tidwall/redcon.c

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <math.h>

#ifdef USEMT
#include <pthread.h>
#endif /* USEMT */

#include <string.h>
#include "redcon.h"
#include "hashmap.h"
#include "match.h"

void *xmalloc(size_t size) {
    void *mem = malloc(size);
    if (!mem) {
        fprintf(stderr, "* out of memory\n");
        exit(1);
    }
    return mem;
}

void xfree(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}

struct server {
#ifdef USEMT
    pthread_rwlock_t rwlock;
#endif /* USEMT */
    uint64_t next_check;
    struct hashmap *pairs;
    int64_t now;
};

struct pair {
    int hasex:1;
    int onstack:1;
    int keylen:29;
    int vallen:29;
    // char key[];    // keylen+1
    // char val[];    // vallen+1
    // double expire;
};

struct pair *pair_new(const char *key, int keylen, 
                      const char *val, int vallen, 
                      double expires)
{
    size_t datasz = keylen+1+vallen+1;
    if (expires > 0) {
        datasz += sizeof(double);
    }
    struct pair *pair = xmalloc(sizeof(struct pair)+datasz);
    pair->onstack = 0;
    pair->hasex = expires > 0 ? 1 : 0;
    pair->keylen = keylen;
    pair->vallen = vallen;
    char *data = ((char *)pair)+sizeof(struct pair);
    memcpy(data, key, keylen);
    data[keylen] = '\0';
    memcpy(data+keylen+1, val, vallen);
    data[keylen+1+vallen] = '\0';
    if (expires > 0) {
        memcpy(data+keylen+1+vallen+1, &expires, sizeof(double));
    }
    return pair;
}

#define alloca_pair() (alloca(sizeof(struct pair)+52))

struct pair *pair_new_forkey(const char *key, int keylen, struct pair *spair) {
    if (keylen > 50) {
        return pair_new(key, keylen, NULL, 0, 0);
    }
    // avoid allocation for small keys
    spair->onstack = 1;
    spair->hasex = 0;
    spair->keylen = keylen;
    spair->vallen = keylen;
    char *data = ((char*)spair)+sizeof(struct pair);
    memcpy(data, key, keylen);
    data[keylen] = '\0';
    data[keylen+1] = '\0';
    return spair;
}

void pair_free(struct pair *pair) {
    if (!pair || pair->onstack) return;
    xfree(pair);
}

const char *pair_key(struct pair *pair) {
    return ((char *)pair) + sizeof(struct pair);
}

const char *pair_val(struct pair *pair) {
    return pair_key(pair) + pair->keylen + 1;
}

double pair_expire(struct pair *pair) {
    if (!pair->hasex) {
        return 0;
    }
    return *((double*)(pair_val(pair) + pair->vallen + 1));
}


int64_t pair_ttl(struct pair *pair, struct server *server) {
    if (!pair->hasex) {
        return -1;
    }
    double expire = *((double*)(pair_val(pair) + pair->vallen + 1));
    double ttl = expire - server->now;
    if (ttl < 0) {
        return -2;
    }
    return (int64_t)ttl;
}


uint64_t key_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    struct pair *p = *((struct pair **)item);
    return hashmap_murmur(pair_key(p), p->keylen, seed0, seed1);
}

int key_compare(const void *a, const void *b, void *udata) {
    struct pair *pa = *((struct pair **)a);
    struct pair *pb = *((struct pair **)b);
    int minkeylen = pa->keylen < pb->keylen ? pa->keylen : pb->keylen;
    int cmp = memcmp(pair_key(pa), pair_key(pb), minkeylen);
    if (cmp == 0) {
        cmp = pa->keylen < pb->keylen ? -1 :pa->keylen > pb->keylen ? 1 : cmp;
    }
    return cmp;
}

int64_t tick(void *udata) {
    struct server *server = udata;
    server->now = (double)redcon_now() / 1e9;
    int npairs = hashmap_count(server->pairs);
    int count = 0;
    int dels = 0;
    while (npairs > 0 && count < 100) {
        struct pair **pval = hashmap_probe(server->pairs, server->next_check++);
        if (pval) {
            if ((*pval)->hasex && pair_expire(*pval) < server->now) {
                hashmap_delete(server->pairs, pval);
                // BROADCAST "DEL key"
                dels++;
                npairs--;
            }
            count++;
        }
    }
    if (dels > 25) {
        return 0; 
    }
    return 50e6; // back off for 50 ms
}

void serving(const char **addrs, int naddrs, void *udata) {
    for (int i = 0; i < naddrs; i++) {
        printf("* Listening at %s\n", addrs[i]);
    }
    printf("* Ready to accept connections\n");
}

void error(const char *msg, bool fatal, void *udata) {
    fprintf(stderr, "- %s\n", msg);
}

bool argtoint(struct redcon_args *args, int index, int64_t *x) {
    size_t arglen = 0;
    const char *arg = redcon_args_at(args, index, &arglen);
    if (strlen(arg) != arglen) return false;
    char *end = NULL;
    long long res = strtoll(arg, &end, 10);
    if (end != arg+arglen) return false;
    if (x) *x = res;
    return true;
}

struct setopts {
    double expire;
    bool nx;
    bool xx;
    bool keepttl;
};

bool parse_getopts(struct redcon_conn *conn, struct redcon_args *args, 
                   struct setopts *opts, struct server *server) 
{
    *opts = (struct setopts) { 0 };
    int nargs = redcon_args_count(args);
    for (int i = 3; i < nargs; i++) {
        bool ex = redcon_args_eq(args, i, "ex");
        bool px = !ex && redcon_args_eq(args, i, "px");
        if (ex || px) {
            if (opts->keepttl) {
                redcon_conn_write_error(conn, "ERR syntax error");
                return false; 
            }
            i++; 
            if (i == nargs) {
                redcon_conn_write_error(conn, "ERR syntax error");
                return false; 
            }
            size_t alen = 0;
            const char *arg = redcon_args_at(args, i, &alen);
            char *end = NULL;
            double x = strtod(arg, &end);
            if (alen != strlen(arg) || end != arg+alen) {
                redcon_conn_write_error(conn, 
                    "ERR value is not an integer or out of range");
                return false;
            } else if (x <= 0 || fpclassify(x) != FP_NORMAL) {
                redcon_conn_write_error(conn, "ERR invalid expire time in set");
                return false;
            }
            // opts->expire = (ex ? x : x / 1000.0) + server->now;
            ex = true;
        } else if (redcon_args_eq(args, i, "nx")) {
            if (opts->xx) {
                redcon_conn_write_error(conn, "ERR syntax error");
                return false; 
            }
            opts->nx = true;
        } else if (redcon_args_eq(args, i, "xx")) {
            if (opts->nx) {
                redcon_conn_write_error(conn, "ERR syntax error");
                return false; 
            }
            opts->xx = true;
        } else if (redcon_args_eq(args, i, "keepttl")) {
            if (opts->expire > 0) {
                redcon_conn_write_error(conn, "ERR syntax error");
                return false; 
            }
            opts->keepttl = true;
        }
    }
    if (opts->keepttl || opts->nx || opts->xx) {
        struct pair *spair = alloca_pair();
        size_t keylen;
        const char *key = redcon_args_at(args, 1, &keylen);
        struct pair *pkey = pair_new_forkey(key, keylen, spair);
        struct pair **pval = hashmap_get(server->pairs, &pkey);
        pair_free(pkey);
        pval = pval && pair_ttl(*pval, server) > -2 ? pval : NULL;
        if ((pval && opts->nx) || (!pval && opts->xx)) { 
            redcon_conn_write_null(conn);
            return false;
        }
        opts->expire = pval && opts->keepttl ? 
                       pair_expire(*pval) : 
                       opts->expire;
    }
    return true;
}

// SET key value [EX seconds|PX milliseconds] [NX|XX] [KEEPTTL]
void cmdSET(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    struct server *server = udata;
    if (redcon_args_count(args) < 3) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
        return;
    }
    size_t keylen, vallen;
    const char *key = redcon_args_at(args, 1, &keylen);
    const char *val = redcon_args_at(args, 2, &vallen);
    struct setopts opts = { 0 };
    if (redcon_args_count(args) > 3) {
        if (!parse_getopts(conn, args, &opts, server)) {
            return;
        }
    }
    struct pair *pair = pair_new(key, keylen, val, vallen, opts.expire);
    struct pair **prev = hashmap_set(server->pairs, &pair);
    if (prev) {
        pair_free(*prev);
    }
    redcon_conn_write_string(conn, "OK");
}

// GET key
void cmdGET(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    struct server *server = udata;
    if (redcon_args_count(args) != 2) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
        return;
    }
    struct pair *spair = alloca_pair();
    size_t keylen;
    const char *key = redcon_args_at(args, 1, &keylen);
    struct pair *pkey = pair_new_forkey(key, keylen, spair);
    struct pair **pval = hashmap_get(server->pairs, &pkey);
    pair_free(pkey);
    if (pval && pair_ttl(*pval, server) > -2) {
        redcon_conn_write_bulk(conn, pair_val(*pval), (*pval)->vallen);
    } else {
        redcon_conn_write_bulk(conn, NULL, 0);
    }
}

// TTL key
void cmdTTL(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    struct server *server = udata;
    if (redcon_args_count(args) != 2) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
        return;
    }
    struct pair *spair = alloca_pair();
    size_t keylen;
    const char *key = redcon_args_at(args, 1, &keylen);
    struct pair *pkey = pair_new_forkey(key, keylen, spair);
    struct pair **pval = hashmap_get(server->pairs, &pkey);
    pair_free(pkey);
    if (pval) {
        redcon_conn_write_int(conn, pair_ttl(*pval, server));
    } else {
        redcon_conn_write_int(conn, -2);
    }
}

// DEL key [key...]
void cmdDEL(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    struct server *server = udata;
    if (redcon_args_count(args) < 2) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
        return;
    }
    struct pair *spair = alloca_pair();
    int ndels = 0;
    int nargs =  redcon_args_count(args);
    for (int i = 1; i < nargs; i++) {
        size_t keylen;
        const char *key = (char*)redcon_args_at(args, i, &keylen);
        struct pair *pkey = pair_new_forkey(key, keylen, spair);
        struct pair **pval = hashmap_delete(server->pairs, &pkey);
        if (pval) {
            if (pair_ttl(*pval, server) > -2) {
                ndels++;
            }
            pair_free(*pval);
        }
        pair_free(pkey);
    }
    redcon_conn_write_int(conn, ndels);
}

struct keysctx {
    struct server *server;
    struct buf writer;
    const char *pat;
    size_t plen;
    int count;
};

bool keysiter(const void *item, void *udata) {
    struct keysctx *ctx = (struct keysctx *)udata;
    struct pair *pair = *((struct pair **)item);
    if (pair_ttl(pair, ctx->server) > -2) {
        if (match(ctx->pat, ctx->plen, pair_key(pair), pair->keylen)) {
            redcon_write_bulk(&ctx->writer, pair_key(pair), pair->keylen);
            ctx->count++;
        }
    }
    return true;
}

// KEYS [pattern]
void cmdKEYS(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    struct server *server = udata;
    if (redcon_args_count(args) != 2) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
        return;
    }
    struct keysctx ctx = { .server = server };
    ctx.pat = redcon_args_at(args, 1, &ctx.plen);
    hashmap_scan(server->pairs, keysiter, &ctx);
    redcon_conn_write_array(conn, ctx.count);
    redcon_conn_write_raw(conn, ctx.writer.data, ctx.writer.len);
    buf_clear(&ctx.writer);
}

// PING [message]
void cmdPING(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    if (redcon_args_count(args) == 1) {
        redcon_conn_write_string(conn, "PONG");
    } else if (redcon_args_count(args) == 2) {
        size_t len;
        const char *arg = redcon_args_at(args, 1, &len);
        redcon_conn_write_bulk(conn, arg, len);
    } else {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
    }
}

bool flushiter(const void *item, void *udata) {
    xfree(*((struct pair**)item));
    return true;
}

// cmdFLUSHDB
void cmdFLUSHDB(struct redcon_conn *conn, struct redcon_args *args, 
                void *udata)
{
    struct server *server = udata;
    if (redcon_args_count(args) != 1) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
        return;
    }
    hashmap_scan(server->pairs, flushiter, NULL);
    hashmap_free(server->pairs);
    server->pairs = hashmap_new(sizeof(struct pair*), 0, 0, 0, key_hash, 
                                key_compare, NULL, NULL);
    redcon_conn_write_string(conn, "OK");
}

// cmdDBSIZE
void cmdDBSIZE(struct redcon_conn *conn, struct redcon_args *args,
               void *udata)
{
    struct server *server = udata;
    if (redcon_args_count(args) != 1) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
        return;
    }
    size_t count = hashmap_count(server->pairs);
    redcon_conn_write_uint(conn, count);
}

void command(struct redcon_conn *conn, struct redcon_args *args, 
             void *udata) 
{
    typedef void (*handler_fp_t)(struct redcon_conn *conn,
        struct redcon_args *args, void *udata);

    #define FLG_NONE          0x00
    #define FLG_RWLOCK        0x01
    #define FLG_EXCLUSIVE     0x02

    struct {
        const char     *command;
        handler_fp_t    handler;
        int             flags;
    } commands[] = {
        { "get",        cmdGET,       (FLG_RWLOCK) },
        { "set",        cmdSET,       (FLG_RWLOCK | FLG_EXCLUSIVE) },
        { "del",        cmdDEL,       (FLG_RWLOCK | FLG_EXCLUSIVE) },
        { "ttl",        cmdTTL,       (FLG_RWLOCK) },
        { "keys",       cmdKEYS,      (FLG_RWLOCK) },
        { "dbsize",     cmdDBSIZE,    (FLG_RWLOCK) },
        { "flushdb",    cmdFLUSHDB,   (FLG_RWLOCK | FLG_EXCLUSIVE) },
        { "ping",       cmdPING,      (FLG_NONE) },
    };

    for (int idx = 0; idx < (sizeof(commands) / sizeof(commands[0])); ++idx) {
      if (redcon_args_eq(args, 0, commands[idx].command)) {
#ifdef USEMT
        #define HAS_FLAG(flags, flag)   ((flags & (flag)) == (flag))
        struct server *server = udata;
        if (HAS_FLAG(commands[idx].flags, FLG_RWLOCK)) {
            if (HAS_FLAG(commands[idx].flags, FLG_EXCLUSIVE)) {
                pthread_rwlock_wrlock(&server->rwlock);
            } else {
                pthread_rwlock_rdlock(&server->rwlock);
            }
        }
#endif /* USEMT */

        commands[idx].handler(conn, args, udata);

#ifdef USEMT
        if (HAS_FLAG(commands[idx].flags, FLG_RWLOCK)) {
            pthread_rwlock_unlock(&server->rwlock);
        }
        #undef HAS_FLAG
#endif /* USEMT */

        return;
      }
    }

    redcon_conn_write_error(conn, "ERR unknown command");

    #undef FLG_EXCLUSIVE
    #undef FLG_RWLOCK
    #undef FLG_NONE
}

int main() {
    // do-or-die allocator
    hashmap_set_allocator(xmalloc, xfree);
    redcon_set_allocator(xmalloc, xfree);

    struct server server = { 0 };
    server.pairs = hashmap_new(sizeof(struct pair *), 0, 0, 0, 
                               key_hash, key_compare, NULL, NULL);
    struct redcon_events evs = {
        .tick = tick,
        .serving = serving,
        .command = command,
        .error = error,
    };
    const char *addrs[] = { 
        "tcp://localhost:6380",
    };
#ifdef USEMT
    pthread_rwlock_init(&server.rwlock, 0);
    redcon_main_mt(addrs, sizeof(addrs)/sizeof(char*), evs, &server, 0);
#else
    redcon_main(addrs, sizeof(addrs)/sizeof(char*), evs, &server);
#endif /* USEMT */
}
