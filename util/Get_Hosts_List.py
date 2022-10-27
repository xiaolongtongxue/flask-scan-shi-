"""
@File    ：Get_Hosts_List.py
@Author  ：TXK
@Date    ：2022/10/20 12:51 
"""
# -*- coding: UTF-8 -*-
from bean.static import *


def get_hosts_list(hosts: str):
    tmp_ = None
    if ":" in hosts:
        # The ip is IPv6 Address,Get it directly
        return [hosts]
    elif "," in hosts:
        ends = hosts.split(",")
        for end in ends:
            tmp = end.split(".")
            # The num is Bigger than 255 or The length of Ip is more than 4.
            if len(tmp) != 4:
                return IPV4_FORMAT_ERROR
            for tmp_ in tmp:
                # Some num can not be int,So Error
                if not tmp_.isdigit() or int(tmp_) >= 255:
                    return IPV4_FORMAT_ERROR
            if tmp_ == 0:  # 0限制
                return IPV4_FORMAT_ERROR
        return ends
    elif "/" in hosts:
        ends = hosts.split(".")
        if len(ends) != 4 or len(ends[3].split("/")) != 2:
            # The length of Ip is error
            return IPV4_FORMAT_ERROR
        num_go = [ends[0], ends[1], ends[2], ends[3].split("/")[0], ends[3].split("/")[1]]
        nums = []
        for tmp in num_go:
            if not tmp.isdigit():
                # Some num can not be int,So Error
                return IPV4_FORMAT_ERROR
        for num_go_ in num_go:
            nums.append(int(num_go_))
            if int(num_go_) >= 255:
                return IPV4_FORMAT_ERROR
        if nums[4] < MAX_ALLOW_SCAN:
            # Only allow too scan
            return TARGET_TOO_MANY
        if nums[4] >= MIN_MASK_NUM:
            return MIN_MASK_ERROR
        import ipaddress
        ip_list = []
        try:
            net = ipaddress.ip_network(hosts)
        except ValueError:
            return IP_VALUE_ERROR
        for ip in net:
            if str(ip)[-1] == '0':
                continue
            ip_list.append(str(ip))
        return ip_list
    else:
        return [hosts]


def to_nmap_get_hosts(hosts: str):
    if "," in hosts:
        ips = hosts.split(",")
        hosts = ""
        for ip in ips:
            hosts += ip + " "
    return hosts
