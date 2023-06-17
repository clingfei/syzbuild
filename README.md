# syzbuild

自动尝试爬取[syzbot](https://syzkaller.appspot.com)中的bug并构建漏洞复现/调试环境

主要包括：
1. kernel(源代码/vmlinux/bzImage)
2. 文件系统
3. syz-execprog/syz-executor/syz-fuzzer 漏洞复现必备
4. repro.prog/repro.c
5. 漏洞复现的结果以及现场

使用方法：

```sh
python3 main.py -u https://syzkaller.appspot.com/bug\?extid\=0b7937459742a0a4cffd
```
成功将会在`work/completed/hash/dump`下生成所有上述所需


```sh
-u 指定爬取的url
--debug 打印log
--force 无论如何删除原始环境重新构建
--max 使用最多多少个核心编译内核和syzkaller
```

目前一堆垃圾bug，谨慎使用，不断迭代ing

## acknowledgment
基于[syzscope](https://github.com/plummm/SyzScope)