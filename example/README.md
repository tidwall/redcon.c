# Redis clone

A fast simple Redis clone for the purpose of demonstrating the [redcon.c](https://github.com/tidwall/redcon.c) framework. 

## Features

- Lightweight
- Single-threaded
- High throughput

The following Redis commands are supported:

```
SET key value [EX seconds|PX milliseconds] [NX|XX] [KEEPTTL]
GET key
DEL key [key ...]
KEYS pattern
PING [message]
FLUSHDB
DBSIZE
QUIT
```

## Install

Clone the respository and then use [pkg.sh](https://github.com/tidwall/pkg.sh) to import dependencies.

```
$ git clone https://github.com/tidwall/redcon.c
$ cd redcon.c/example
$ pkg.sh import
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

The Redis clone used about 7% less memory than Redis 6.06 -- 79.7 MB to 84.8 MB.

The machine is an AWS c5.2xlarge instance (Intel Xeon 3.6 GHz).

The benchmark command looked like:

```
redis-benchmark -q -t set,get -r 1000000 -n 10000000 -p 6379  -P 16   # redis 6.06
redis-benchmark -q -t set,get -r 1000000 -n 10000000 -p 6380  -P 16   # redis clone
```



