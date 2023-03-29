// Copyright 2022 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.
// Documentation at https://github.com/tidwall/redcon.c

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "buf.h"
#include "evio.h"
#include "redcon.h"

#define MAXARGS  1048575
#define MAXARGSZ 536870912

static void *(*_malloc)(size_t) = NULL;
static void (*_free)(void *) = NULL;

#define rcmalloc (_malloc?_malloc:malloc)
#define rcfree (_free?_free:free)

// redcon_set_allocator allows for configuring a custom allocator for
// all redcon library operations. This function, if needed, should be called
// only once at startup and a prior to calling any library functions
void redcon_set_allocator(void *(malloc)(size_t), void (*free)(void*)) {
    _malloc = malloc;
    _free = free;
    evio_set_allocator(malloc, free);
    buf_set_allocator(malloc, free);
}

struct redcon_args {
    struct buf *bufs;
    int len, cap;
};

struct redcon_conn {
    bool closed;
    struct evio_conn *econn;
    struct buf packet;
    struct buf wrbuf;
    void *udata;
    int nls;    
    struct redcon_args args;
};


struct mainctx {
    void *udata;
    struct redcon_events *events;
};

const char *redcon_args_at(struct redcon_args *args, int idx, size_t *len) {
    if (len) *len = args->bufs[idx].len;
    return args->bufs[idx].data;
}

int redcon_args_count(struct redcon_args *args) {
    return args->len;
}

bool redcon_args_eq(struct redcon_args *args, int index, const char *str) {
    if (index >= redcon_args_count(args)) {
        return false;
    }
    size_t slen = strlen(str); 
    size_t arglen = 0;
    const char *arg = redcon_args_at(args, index, &arglen);
    if (arglen != slen) {
        return false;
    }
    for (size_t i = 0; i < slen ; i++) {
        if (tolower(str[i]) != tolower(arg[i])) {
            return false;
        }
    }
    return true;
}

static bool append_arg(struct redcon_args *args, const char *data, size_t len) {
    if (args->len == args->cap) {
        size_t cap = args->cap ? args->cap * 2 : 1;
        struct buf *bufs = rcmalloc(cap * sizeof(struct buf));
        if (!bufs) {
            return false;
        }
        memcpy(bufs, args->bufs, args->len * sizeof(struct buf));
        memset(&bufs[args->len], 0, (cap-args->len) * sizeof(struct buf));
        rcfree(args->bufs);
        args->bufs = bufs;
        args->cap = cap;
    }
    args->bufs[args->len].len = 0;
    if (!buf_append(&args->bufs[args->len], data, len)) {
        return false;
    }
    args->len++;
    return true;
}

int64_t redcon_now() {
    return evio_now();
}

static struct redcon_conn *redcon_conn_new(struct evio_conn *econn) {
    struct redcon_conn *conn = rcmalloc(sizeof(struct redcon_conn));
    if (!conn) {
        return NULL;
    }
    memset(conn, 0, sizeof(struct redcon_conn));
    conn->econn = econn;
    return conn;
}

static void redcon_conn_free(struct redcon_conn *conn) {
    if (!conn) {
        return;
    }
    buf_clear(&conn->packet);
    buf_clear(&conn->wrbuf);
    for (int i = 0 ; i < conn->args.cap; i++) {
        buf_clear(&conn->args.bufs[i]);
    }
    rcfree(conn->args.bufs);
    rcfree(conn);
}

void redcon_conn_set_udata(struct redcon_conn *conn, void *udata) {
    conn->udata = udata;
}

void *redcon_conn_udata(struct redcon_conn *conn) {
    return conn->udata;
}

void redcon_conn_close(struct redcon_conn *conn) {
    if (conn->closed) return;
    conn->closed = true;
    evio_conn_close(conn->econn);
}

const char *redcon_conn_addr(struct redcon_conn *conn) {
    return evio_conn_addr(conn->econn);
}

static int64_t tick(void *udata) {
    struct mainctx *ctx = udata;
    if (ctx->events->tick) {
        return ctx->events->tick(ctx->udata);
    } else {
        return 50e6; // back off for 50 ms
    }
}

static bool sync(void *udata) {
    struct mainctx *ctx = udata;
    if (ctx->events->sync) {
        return ctx->events->sync(ctx->udata);
    } else {
        return true;
    }
}

static void opened(struct evio_conn *econn, void *udata) {
    struct mainctx *ctx = udata;
    struct redcon_conn *conn = redcon_conn_new(econn);
    if (!conn) {
        evio_conn_close(econn);
        return;
    }
    evio_conn_set_udata(econn, conn);
    if (ctx->events->opened) {
        ctx->events->opened(conn, ctx->udata);
    }
}

static void closed(struct evio_conn *econn, void *udata) {
    struct mainctx *ctx = udata;
    struct redcon_conn *conn = evio_conn_udata(econn);
    if (conn) {
        conn->closed = true;
        if (ctx->events->closed) {
           ctx->events->closed(conn, ctx->udata);
        }   
        redcon_conn_free(conn);
    }
}

static void serving(const char **addrs, int naddrs, void *udata) {
    struct mainctx *ctx = udata;
    if (ctx->events->serving) {
        ctx->events->serving(addrs, naddrs, ctx->udata);
    }
}

static void error(const char *message, bool fatal, void *udata) {
    struct mainctx *ctx = udata;
    if (ctx->events->error) {
        ctx->events->error(message, fatal, ctx->udata);
    }
}

// returns the number of bytes read from data.
// returns SIZE_MAX on error
// returns 0 when there isn't enough data to complete a command.
static size_t telnet_parse(char *data, size_t len, struct redcon_conn *conn, 
                           struct redcon_args *args)
{
    char *err = NULL;
    struct buf arg = { 0 };
    args->len = 0;
    bool inarg = false;
    char quote = '\0';
    for (size_t i = 0; i < len; i++) {
        char ch = data[i];
        if (inarg) {
            if (quote) {
                if (ch == '\n') goto fail_quotes;
                if (ch == quote) { 
                    if (!append_arg(args, arg.data, arg.len)) goto fail;
                    if (args->len > MAXARGS) goto fail_nargs;
                    arg.len = 0;
                    i++;
                    if (i == len) break;
                    ch = data[i];
                    inarg = false;
                    if (ch == '\n') {
                        i--;
                        continue;
                    }
                    if (!isspace(ch)) goto fail_quotes;
                    continue;
                } else if (ch == '\\') {
                    i++;
                    if (i == len) break;
                    ch = data[i];
                    switch (ch) {
                    case 'n': ch = '\n'; break;
                    case 'r': ch = '\r'; break;
                    case 't': ch = '\t'; break;
                    }
                }
                if (!buf_append_byte(&arg, ch)) goto fail;
                if (arg.len > MAXARGSZ) goto fail_argsz;
            } else {
                if (ch == '"' || ch == '\'') {
                    quote = ch;
                } else if (isspace(ch)) {
                    if (!append_arg(args, arg.data, arg.len)) goto fail;
                    if (args->len > MAXARGS) goto fail_nargs;
                    arg.len = 0;
                    if (ch == '\n') break;
                    inarg = false;
                } else {
                    if (!buf_append_byte(&arg, ch)) goto fail;
                    if (arg.len > MAXARGSZ) goto fail_argsz;
                }
            }
        } else {
            if (ch == '\n') {
                buf_clear(&arg);
                return i+1;
            }
            if (isspace(ch)) continue;
            inarg = true;
            if (ch == '"' || ch == '\'') {
                quote = ch;
            } else {
                quote = 0;
                if (!buf_append_byte(&arg, ch)) goto fail;
                if (arg.len > MAXARGSZ) goto fail_argsz;
            }
        }
    }
    buf_clear(&arg);
    return 0;

fail_quotes:
    if (!err) err = "ERR Protocol error: unbalanced quotes in request";
fail_nargs:
    if (!err) err = "ERR Protocol error: invalid multibulk length";
fail_argsz:
    if (!err) err = "ERR Protocol error: invalid bulk length";
fail:
    if (err) {
        redcon_conn_write_error(conn, err);
    }
    buf_clear(&arg);
    return SIZE_MAX;
}

// returns the number of bytes read from data.
// returns SIZE_MAX on error
// returns 0 when there isn't enough data to complete a command.
static size_t resp_parse(char *data, size_t len, struct redcon_conn *conn, 
                         struct redcon_args *args)
{
    args->len = 0;
    size_t i = 0;
    if (len == 0 || data[i] != '*') {
        return SIZE_MAX;
    }
    i++;
    if (i == len) return 0;
    if (!memchr(data+i, '\n', len-i)) return 0;
    char *end = NULL;
    long nargs = strtol(data+i, &end, 10);
    if (end == data+i || nargs > MAXARGS || 
        end[0] != '\r' || end[1] != '\n') 
    {
        redcon_conn_write_error(conn, 
            "ERR Protocol error: invalid multibulk length");
        return SIZE_MAX;
    }
    i += (end-(data+i))+2;
    // loop through each argument
    for (int j = 0; j < nargs; j++) {
        // read bulk length line
        if (i == len) return 0;
        if (data[i] != '$') {
            char str[64];
            snprintf(str, sizeof(str), 
                "ERR Protocol error: expected '$', got '%c'", data[i]);
            redcon_conn_write_error(conn, str);
            return SIZE_MAX;
        }
        i++;
        if (i == len) return 0;
        if (!memchr(data+i, '\n', len-i)) return 0;
        long nbytes = strtol(data+i, &end, 10);
        if (end == data+i || nbytes > MAXARGSZ || 
            end[0] != '\r' || end[1] != '\n') 
        {
            redcon_conn_write_error(conn, 
                "ERR Protocol error: invalid bulk length");
            return SIZE_MAX;
        }
        i += (end-(data+i))+2;
        if (i+nbytes+2 > len) return 0;
        if (!append_arg(args, data+i, nbytes)) {
            return SIZE_MAX;
        }
        i += nbytes+2;
    }
    return i;
}

static void data(struct evio_conn *econn, 
                 const void *edata, size_t elen, void *udata)
{
    struct mainctx *ctx = udata;
    struct redcon_conn *conn = evio_conn_udata(econn);
    if (!conn || conn->closed) {
        goto close;
    }

    char *data;
    size_t len;
    bool copied;

    if (conn->packet.len == 0) {
        data = (char*)edata;
        len = elen;
        copied = false;
    } else {
        if (!buf_append(&conn->packet, edata, elen)) {
            goto close;
        }
        len = conn->packet.len;
        data = conn->packet.data;
        copied = true;
    }

    while (len > 0 && !conn->closed) {
        size_t n;
        if (data[0] != '*') {
            n = telnet_parse(data, len, conn, &conn->args);
        } else {
            n = resp_parse(data, len, conn, &conn->args);
        }
        if (n == 0) {
            break;
        }
        if (n == SIZE_MAX) {
            conn->closed = true;
            break;
        }
        if (conn->args.len > 0) {            
            if (redcon_args_eq(&conn->args, 0, "quit")) {
                redcon_conn_write_string(conn, "OK");
                conn->closed = true;
                break;
            }
            if (ctx->events->command) {
                ctx->events->command(conn, &conn->args, ctx->udata);
            }
        }
        len -= n;
        data += n;
    }
    if (conn->closed) {
        goto close;
    }

    if (len == 0) {
        if (copied) {
            if (conn->packet.cap > 4096) {
                buf_clear(&conn->packet);
            }
            conn->packet.len = 0;
        }
    } else {
        if (copied) {
            memmove(conn->packet.data, data, len);
            conn->packet.len = len;
        } else {
            if (!buf_append(&conn->packet, data, len)) {
                goto close;
            }
        }
    }
    return;
close:
    evio_conn_close(econn);
    return;
}

void redcon_main_mt(const char **addrs, int naddrs, 
                    struct redcon_events events, void *udata, int nthreads) 
{
    struct mainctx ctx = {
        .udata = udata,
        .events = &events,
    };
    struct evio_events eevents = {
        .tick = events.tick?tick:NULL,
        .sync = events.sync?sync:NULL,
        .data = data,
        .opened = opened,
        .closed = closed,
        .serving = events.serving?serving:NULL,
        .error = events.error?error:NULL,
    };
    evio_main_mt(addrs, naddrs, eevents, &ctx, nthreads); 
}

void redcon_main(const char **addrs, int naddrs, struct redcon_events events, 
                 void *udata) 
{
    redcon_main_mt(addrs, naddrs, events, udata, 1);
}

static bool writeln(struct buf *buf, char ch, const void *data, ssize_t len) {
    if (len < 0) {
        len = strlen(data);
    }
    if (!buf_append_byte(buf, ch)) {
        return false;
    }
    size_t mark = buf->len;
    if (!buf_append(buf, data, len)) {
        return false;
    }
    for (size_t i = mark; i < buf->len; i++) {
        if (buf->data[i] < ' ') {
            buf->data[i] = ' ';
        }
    }
    return buf_append_byte(buf, '\r') && buf_append_byte(buf, '\n');
}

const char *z64toa(uint64_t n, bool sign, char *str) {
    int i = 0;
    do {
        str[i++] = n % 10 + '0';
    } while ((n /= 10) > 0);
    if (sign) str[i++] = '-';
    // reverse the characters
    for (int j = 0, k = i-1; j < k; j++, k--) {
        char ch = str[j];
        str[j] = str[k];
        str[k] = ch;
    }
    str[i] = '\0';
    return str;
} 

const char *i64toa(int64_t n, char *str) {
    if (n < 0) {
        return z64toa(n * -1, true, str);
    } else {
        return z64toa(n, false, str);
    }
}

const char *u64toa(uint64_t n, char *str) {
    return z64toa(n, false, str);
}

bool redcon_write_array(struct buf *buf, int count) {
    char str[32];
    return writeln(buf, '*', i64toa(count, str), -1);
}

bool redcon_write_string(struct buf *buf, const char *str) {
    return writeln(buf, '+', str, -1);
}

bool redcon_write_error(struct buf *buf, const char *err) {
    return writeln(buf, '-', err, -1);
}

bool redcon_write_uint(struct buf *buf, uint64_t value) {
    char str[32];
    return writeln(buf, ':', u64toa(value, str), -1);
}

bool redcon_write_int(struct buf *buf, int64_t value) {
    char str[32];
    return writeln(buf, ':', i64toa(value, str), -1);
}

bool redcon_write_null(struct buf *buf) {
    return buf_append(buf, "$-1\r\n", 5);
}

bool redcon_write_bulk(struct buf *buf, const void *data, ssize_t len) {
    if (data == NULL) {
        return redcon_write_null(buf);    
    }
    if (len < 0) {
        len = strlen(data);
    }
    char str[32];
    return writeln(buf, '$', i64toa(len, str), -1) &&
           buf_append(buf, data, len) && 
           buf_append(buf, "\r\n", 2);
}

#define rwrite(func, ...) { \
    if (conn->closed) return; \
    if (!func(&conn->wrbuf, ##__VA_ARGS__)) { \
        conn->closed = true; \
        return; \
    } \
    evio_conn_write(conn->econn, conn->wrbuf.data, conn->wrbuf.len); \
    if (conn->wrbuf.cap > 4096) { \
        buf_clear(&conn->wrbuf); \
    } else { \
        conn->wrbuf.len = 0; \
    } \
}

void redcon_conn_write_array(struct redcon_conn *conn, int count) {
    rwrite(redcon_write_array, count);
}

void redcon_conn_write_string(struct redcon_conn *conn, const char *str) {
    rwrite(redcon_write_string, str);
}

void redcon_conn_write_error(struct redcon_conn *conn, const char *err) {
    rwrite(redcon_write_error, err);
}

void redcon_conn_write_uint(struct redcon_conn *conn, uint64_t value) {
    rwrite(redcon_write_uint, value);
}

void redcon_conn_write_int(struct redcon_conn *conn, int64_t value) {
    rwrite(redcon_write_int, value);
}

void redcon_conn_write_bulk(struct redcon_conn *conn, const void *data, 
                            ssize_t len)
{
    rwrite(redcon_write_bulk, data, len);
}

void redcon_conn_write_raw(struct redcon_conn *conn, const void *data, 
                           ssize_t len)
{
    rwrite(buf_append, data, len);
}

void redcon_conn_write_null(struct redcon_conn *conn) {
    rwrite(redcon_write_null);
}
