<p align="center">
<img 
    src="logo.png" 
    width="336" border="0" alt="REDCON">
<br>
</p>

<p align="center">Fast Redis compatible server framework for C</p>


Redcon is a custom Redis server framework that is fast and simple to use. This is a C version of the [original Redcon](https://github.com/tidwall/redcon), and is built on top of [evio.c](https://github.com/tidwall/evio.c).


## Features

- Create a [Fast](#benchmarks) custom Redis compatible server in C
- Simple interface
- Single-theaded
- Super lightweight
- Support for pipelining and telnet commands
- Works with Redis clients such as [redigo](https://github.com/garyburd/redigo), [redis-py](https://github.com/andymccurdy/redis-py), [node_redis](https://github.com/NodeRedis/node_redis), and [jedis](https://github.com/xetorthio/jedis)

## Install

Clone this respository and then use [pkg.sh](https://github.com/tidwall/pkg.sh)
to import dependencies.

```
$ git clone https://github.com/tidwall/redcon.c
$ cd redcon.c/
$ pkg.sh import
```

## Example

Here's a simple Redis clone. Save the following file to `clone.c` 

*Check out [example/clone.c](/example) for a more robust example*.

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "redcon.h"
#include "hashmap.h"

void *zmalloc(size_t size);

// keyspace is a collection of all keys. (github.com/tidwall/hashmap.c)
struct hashmap *keyspace; 

void cmdSET(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    if (redcon_args_count(args) != 3) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
    } else {
        // Each key/value item is a single allocation of two contiguous 
        // series of bytes, the first is a c-string and the second is binary.
        int vallen;
        const char *key = redcon_args_at(args, 1, NULL);
        const char *val = redcon_args_at(args, 2, &vallen);
        char *item = zmalloc(strlen(key)+5+vallen);
        strcpy(item, key); 
        *(int32_t*)(item+strlen(item)+1) = vallen;
        memcpy(item+strlen(item)+5, val, vallen);
        char **prev = hashmap_set(keyspace, &item);
        if (prev) free(*prev);
        redcon_conn_write_string(conn, "OK");
    }
}

void cmdGET(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    if (redcon_args_count(args) != 2) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
    } else {
        const char *key = redcon_args_at(args, 1, NULL);
        char **item = hashmap_get(keyspace, &key);
        if (!item) {
            redcon_conn_write_null(conn);
        } else {
            char *val = *item+strlen(*item)+5;
            int vallen = *(int32_t*)(*item+strlen(*item)+1);
            redcon_conn_write_bulk(conn, val, vallen);
        }
    }
}

void cmdDEL(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    if (redcon_args_count(args) != 2) {
        redcon_conn_write_error(conn, "ERR wrong number of arguments");
    } else {
        const char *key = redcon_args_at(args, 1, NULL);
        char **prev = hashmap_delete(keyspace, &key);
        if (!prev) {
            redcon_conn_write_int(conn, 0);
        } else {
            free(*prev);
            redcon_conn_write_int(conn, 1);
        }
    }
}

void cmdPING(struct redcon_conn *conn, struct redcon_args *args, void *udata) {
    redcon_conn_write_string(conn, "PONG");
}

void command(int64_t nano, struct redcon_conn *conn, struct redcon_args *args, void *udata) {
         if (redcon_args_eq(args, 0, "set"))  cmdSET(conn, args, udata);
    else if (redcon_args_eq(args, 0, "get"))  cmdGET(conn, args, udata);
    else if (redcon_args_eq(args, 0, "del"))  cmdDEL(conn, args, udata);
    else if (redcon_args_eq(args, 0, "ping")) cmdPING(conn, args, udata);
    else redcon_conn_write_error(conn, "ERR unknown command");
}

void serving(int64_t nano, const char **addrs, int naddrs, void *udata) {
    printf("* Listening at %s\n", addrs[0]);
}

void error(int64_t nano, const char *msg, bool fatal, void *udata) {
    fprintf(stderr, "- %s\n", msg);
}

uint64_t hash(const void *item, uint64_t seed0, uint64_t seed1) {
    return hashmap_murmur(*(char**)item, strlen(*(char**)item), seed0, seed1);
}

int compare(const void *a, const void *b, void *udata) {
    return strcmp(*(char**)a, *(char**)b);
}

void *zmalloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) abort();
    return ptr;
}

int main() {
    // use do-or-die allocator
    redcon_set_allocator(zmalloc, free);
    hashmap_set_allocator(zmalloc, free);

    keyspace = hashmap_new(sizeof(char *), 0, 0, 0, hash, compare, NULL);
    struct redcon_events evs = {
        .serving = serving,
        .command = command,
        .error = error,
    };
    const char *addrs[] = { 
        "tcp://0.0.0.0:6380",
    };
    redcon_main(addrs, 1, evs, NULL);
}
```

Then build and run the server.

```
$ cc *.c && ./a.out
```

And connect using the [Redis cli](https://redis.io/download).

```
$ redis-cli -p 6380
```

## Benchmarks

For following results were generated using the `redis-benchmark` tool that is provided by the official Redis distribution.

|             | Cmd | Pipeline 1  | Pipeline 8  | Pipeline 16   | Pipeline 32   | Pipeline 64   | Pipeline 128  |
| ----------- | ----| ----------- | ----------- | ------------- | ------------- | ------------- | ------------- |
| Redis 6.06  | SET | 114,467     | 618,432     | 765,284       | 872,984       | 947,724       | 990,307       |
| Redis 6.06  | GET | 114,888     | 692,764     | 898,724       | 1,048,987     | 1,151,277     | 1,208,751     |
| Redis clone | SET | 114,554     | 895,502     | 1,310,787     | 1,670,902     | 1,954,295     | 2,122,295     |
| Redis clone | GET | 114,602     | 894,862     | 1,346,276     | 1,735,809     | 2,046,245     | 2,230,151     |

In my above benchmark test the Redis clone used about 7% less memory than Redis 6.06 -- 79.7 MB to 84.8 MB.

The machine was an AWS c5.2xlarge instance (Intel Xeon 3.6 GHz).

The benchmark command looked like:

```
redis-benchmark -q -t set,get -r 1000000 -n 10000000 -p 6379  -P 16   # redis 6.06
redis-benchmark -q -t set,get -r 1000000 -n 10000000 -p 6380  -P 16   # redis clone
```
