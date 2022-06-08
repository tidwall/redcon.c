// Copyright 2022 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.
// Documentation at https://github.com/tidwall/redcon.c

#ifndef REDCON_H
#define REDCON_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include "buf.h"

struct redcon_conn;

void *redcon_conn_udata(struct redcon_conn *conn);
void redcon_conn_set_udata(struct redcon_conn *conn, void *udata);
void redcon_conn_close(struct redcon_conn *conn);
const char *redcon_conn_addr(struct redcon_conn *conn);
void redcon_conn_write_raw(struct redcon_conn *conn, const void *data, 
                           ssize_t len);
void redcon_conn_write_array(struct redcon_conn *conn, int count);
void redcon_conn_write_string(struct redcon_conn *conn, const char *str);
void redcon_conn_write_error(struct redcon_conn *conn, const char *err);
void redcon_conn_write_uint(struct redcon_conn *conn, uint64_t value);
void redcon_conn_write_int(struct redcon_conn *conn, int64_t value);
void redcon_conn_write_bulk(struct redcon_conn *conn, const void *data, 
                            ssize_t len);
void redcon_conn_write_null(struct redcon_conn *conn);

struct redcon_args;

const char *redcon_args_at(struct redcon_args *args, int index, size_t *len);
int redcon_args_count(struct redcon_args *args);
bool redcon_args_eq(struct redcon_args *args, int index, const char *cmd);

struct redcon_events {
    int64_t (*tick)(void *udata);
    bool (*sync)(void *udata);
    void (*command)(struct redcon_conn *conn, 
                    struct redcon_args *args, void *udata);
    void (*opened)(struct redcon_conn *conn, void *udata);
    void (*closed)(struct redcon_conn *conn, void *udata);
    void (*serving)(const char **addrs, int naddrs, void *udata);
    void (*error)(const char *message, bool fatal, void *udata);
};

void redcon_main(const char **addrs, int naddrs, struct redcon_events events, 
                 void *udata);
void redcon_main_mt(const char **addrs, int naddrs,
                    struct redcon_events events, void *udata, int nthreads);

void redcon_set_allocator(void *(malloc)(size_t), void (*free)(void*));

// general purpose resp message writing

bool redcon_write_array(struct buf *buf, int count);
bool redcon_write_string(struct buf *buf, const char *str);
bool redcon_write_error(struct buf *buf, const char *err);
bool redcon_write_uint(struct buf *buf, uint64_t value);
bool redcon_write_int(struct buf *buf, int64_t value);
bool redcon_write_bulk(struct buf *buf, const void *data, ssize_t len);
bool redcon_write_null(struct buf *buf);

int64_t redcon_now();

#endif
