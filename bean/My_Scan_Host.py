"""
@File    ：My_Scan_Host.py
@Author  ：TXK
@Date    ：2022/10/26 14:59 
"""
# -*- coding: UTF-8 -*-
from datetime import datetime


class my_scan_host:
    def __init__(self, scan_time: datetime, scan_id: str, user_id: str, username: str, byway: int, hosts: str, end: str,
                 errorcode: int):
        self.scan_time = scan_time
        self.scan_id = scan_id
        self.user_id = user_id
        self.username = username
        if byway == 1:
            self.byway = "Scapy"
        elif byway == 2:
            self.byway = "Nmap"
        elif byway == 3:
            self.byway = "Socket"
        else:
            self.byway = ""
        self.hosts = hosts
        try:
            self.end = dict(eval(end))
        except TypeError:
            self.end = None
        self.errorcode = errorcode

    def get_json(self):
        return {
            "Scan_Time": str(self.scan_time),   # 扫描时间
            "Scan_id": self.scan_id,            # 扫描id
            "username": self.username,          # 用户名
            "Scan_Model": self.byway,           # 扫描模式
            "Scan_Hosts": self.hosts,           # 被扫描主机
            "EndText": str(self.end),           # 扫描结果原文
            "ErrorCode": self.errorcode         # 错误代码
        }
