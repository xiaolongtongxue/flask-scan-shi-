"""
@File    ：n_host_alive.py
@Author  ：TXK
@Date    ：2022/10/22 16:00 
"""
# -*- coding: UTF-8 -*-
import nmap

from util.Get_Hosts_List import to_nmap_get_hosts

"""
参数	作用
-O	系统扫描
-V，-v，-D，-d，-p	debug信息
–fuzzy	推测操作系统检测结果
-sT	TCP端口扫描（完整三次握手）
-sU	UDP端口扫描（不回应可能打开，回应则关闭）
-sL	DNS反向解析
-sS	隐藏扫描（半开SYN）
-sP	发现存活主机（直连arp，非直连TCP80，ICMP）
-sO	确定主机协议扫描
-sW	对滑动窗口的扫描
-sA	TCP ACK扫描
-sN	关闭主机扫描（不管是否存活直接扫描）
-sF	fin扫描
-sX	Xmas扫描（fin psh urg为置位）
-sI	完全隐藏（以一个跳板为主机（无流量）扫描另一台主机）
-sV	服务版本
-sC	跟安全有关的脚本
-PN	扫描自己
"""


def n_host_scan_sP(hosts: str, scan_type: str = "-sP"):
    hosts = to_nmap_get_hosts(hosts=hosts)
    if " " in hosts:
        hosts = hosts[0:-1]
    hosts_list = hosts.split(" ")
    nm = nmap.PortScanner()
    nm.scan(hosts=hosts, arguments=scan_type)
    hosts_end = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

    host_alive = []

    for host, status in hosts_end:
        host_alive.append(host)
        # print(host + " is " + status)

    # print(hosts_list)
    # print(host_alive)

    end = {}
    for host in hosts_list:
        if host in host_alive:
            end.update({host: True})
        else:
            end.update({host: False})
    return end


if __name__ == '__main__':
    print(n_host_scan_sP(hosts="127.0.0.1"))
    """
    {'192.168.1.55': False, '192.168.1.101': True}
    """
