# 网络扫描工具 v1.0
## 简介
一个简单的基于python的scapy和socket库编写的网络扫描工具，集成了主机发现、端口扫描和banner探测功能。

## 功能列表
### 主机发现

ARP扫描（局域网）

ICMP扫描（Ping扫描）

### 端口扫描

TCP半开放扫描（SYN扫描）

TCP全开放扫描

UDP扫描

### Banner探测

识别端口服务信息

## 使用方法
确保所有.py文件在同一目录下

运行主程序：

bash

python main.py

按菜单提示选择功能

## 注意
部分功能需要管理员权限

请在合法范围内使用

支持Windows/Linux系统
windows系统需额外安装npmap

npmap网址:https://npcap.com/#download
