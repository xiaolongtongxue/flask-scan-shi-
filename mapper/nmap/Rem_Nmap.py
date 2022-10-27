"""
@File    ：Rem_Nmap.py
@Author  ：TXK
@Date    ：2022/10/25 20:51 
"""
# -*- coding: UTF-8 -*-
import time

from bean.static import *
from dao.Connector import sql_run1
from util.Random_Str import get_random_str


def rem_nmap(user_id: str, hosts: str, end: str, ports: str = None):
    scan_id_value = str(int(time.time() * 10000)) + get_random_str(2)
    if ports is None:
        sql = "INSERT INTO `flask_scan`.`host_scan` (scan_id, userid, byway, hosts, End) " \
              "VALUE (?,?,2,?,?);"
        data = (scan_id_value, user_id, hosts, end)
    else:
        sql = "INSERT INTO `flask_scan`.`ports_scan` (scan_id, userid, byway, hosts, ports, End) " \
              "VALUE (?,?,2,?,?,?);"
        data = (scan_id_value, user_id, hosts, ports, end)
    if sql_run1(sql=sql, data=data) == INSERT_SUCCESSFULLY:
        return True
    else:
        return False
