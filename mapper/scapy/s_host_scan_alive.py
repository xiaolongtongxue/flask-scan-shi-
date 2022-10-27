"""
@File    ：s_host_scan_alive.py
@Author  ：TXK
@Date    ：2022/10/19 15:51
"""
# -*- coding: UTF-8 -*-
from scapy.all import *
from scapy.layers.l2 import ARP

from util.DNS_Query import dns_query
from util.Get_Hosts_List import get_hosts_list
from bean.static import *
from bean.MyThread import MyThread


# 本段中所有可能出现的错误代码：
# 1. DNS_ERROR              DNS解析出错
# 2. IPV4_FORMAT_ERROR      IPv4格式出错
# 3. MIN_MASK_ERROR         子网掩码 大于等于 32
# 4. TARGET_TOO_MANY        传入的子网掩码过小，超过了系统限制
# 5. IP_VALUE_ERROR         使用子网掩码时，请务必保证ip地址对应的主机位的数字置0
def s_host_scan(hosts: str, dns: bool = False):
    if not dns:
        target_list = get_hosts_list(hosts=hosts)
        if not isinstance(target_list, list):
            return target_list
    else:
        target_list = dns_query(host=hosts)
        if not isinstance(target_list, list):
            # DNS Query Error
            return DNS_ERROR
    end = {}
    # print(target_list)
    for target in target_list:
        # print(target)
        t = MyThread(arp_scan, (target, None), arp_scan.__name__)
        t.start()
        end.update(t.get_result())
        # end.update(arp_scan(target))
    return end


def arp_scan(ip, tmp):
    p = ARP(pdst=ip)
    ans = sr1(p, timeout=5, verbose=0)
    if ans is not None:
        """
        # ans.display()
        内容可选项
          hwtype    = 0x1
          ptype     = IPv4
          hwlen     = 6
          plen      = 4
          op        = is-at
          hwsrc     = 18:f2:2c:e6:1d:c7
          psrc      = 192.168.1.1
          hwdst     = 3c:91:80:5f:2f:b5
          pdst      = 192.168.1.103
        """
        return {ip: {
            "end": True,
            "hwsrc": ans.hwsrc,  # 目的MAC
            "psrc": ans.psrc,  # 被测试ip
            "hwdst": ans.hwdst,  # 本机MAC
            "pdst": ans.pdst  # 本机IP
        }}
    else:
        return {ip: False}


if __name__ == '__main__':
    # print(get_hosts_list("192.168.1.0/30"))
    # print(dns_query("baidu.com"))
    # print(arp_scan("192.168.1.1"))
    print(s_host_scan("127.0.0.1,192.168.110.131"))
