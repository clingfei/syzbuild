# syzbuild

自动尝试爬取[syzbot](https://syzkaller.appspot.com)中的bug并构建漏洞复现/调试环境

主要包括：
1. kernel(源代码/vmlinux/bzImage)
2. 文件系统
3. syz-execprog/syz-executor/syz-fuzzer 漏洞复现必备
4. repro.prog/repro.c
5. 漏洞复现的结果以及现场

使用方法：

安装依赖  

```shell
ipdb
IPython
prettytable
portpicker
```

```shell
python3 main.py -u https://syzkaller.appspot.com/bug\?extid\=0b7937459742a0a4cffd -d /home/spark/foobar/
```

最好挂上代理，不然clone不下来
成功将会在下生成所有上述所需
如果需要deploy环境，注意需要设置如下环境变量为本地路径

```shell
UPSTREAM_LINUX
UPSTREAM_SYZKALLER
GCC8
GCC9
GCC10
GCC11
GCC12
CLANG8
CLANG9
CLANG10
CLANG11
CLANG12
......
```

例如：
```shell
export UPSTREAM_SYZKALLER="/home/spark/foobar/syzkaller"
export UPSTREAM_LINUX="/home/spark/foobar/linux"
```

参数解释

```shell
u 指定爬取的url
-d 指定爬取后deploy的位置
-assets 是否下载assets中的内容
--logs 是否下载所有的console_log
--debug 打印log
--force 无论如何删除原始环境重新构建
--max 使用最多多少个核心编译内核和syzkaller
```

目前一堆垃圾bug，谨慎使用，不断迭代ing

## acknowledgment
基于[syzscope](https://github.com/plummm/SyzScope)
