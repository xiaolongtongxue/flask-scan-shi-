"""
@File    ：Rem_Scapy.py
@Author  ：TXK
@Date    ：2022/10/24 20:00 
"""
# -*- coding: UTF-8 -*-
import time

from bean.static import *
from dao.Connector import sql_run1
from util.Random_Str import get_random_str


def rem_scapy(user_id: str, hosts: str, end: str, ports: str = None):
    """
    通过scapy对主机/端口完成扫描之后，便将数据存储进入MySQL数据库
    :param user_id: 请求扫描的用户id
    :param hosts: 请求扫描的主机地址（或地址段）
    :param end: 扫描结果（处理过后的格式化数据）
    :param ports: 扫描的端口内容(如果只是单纯的主机扫描则此项可以留空)
    :return:
    """
    scan_id_value = str(int(time.time() * 10000)) + get_random_str(2)
    if ports is None:
        sql = "INSERT INTO `flask_scan`.host_scan (scan_id, userid, byway, hosts, End) " \
              "VALUE (?,?,1,?,?)"
        data = (scan_id_value, user_id, hosts, end)
    else:
        sql = "INSERT INTO `flask_scan`.ports_scan (scan_id, userid, byway, hosts, ports, End) " \
              "VALUE (?,?,1,?,?,?)"
        data = (scan_id_value, user_id, hosts, ports, end)
    if sql_run1(sql=sql, data=data) == INSERT_SUCCESSFULLY:
        return True
    else:
        return False


def rem_scapy_error(user_id: str, hosts: str, errorcode: int = None, ports: str = None):
    """
    通过scapy对主机/端口完成扫描过程之中出现错误之后，便将和对应错误相关的数据存储进入MySQL数据库
    :param user_id: 请求扫描的用户id
    :param hosts: 请求扫描的主机地址（或地址段）
    :param errorcode: 错误代码（详见bean.static包）
    :param ports: 扫描的端口内容(如果只是单纯的主机扫描则此项可以留空)
    :return:
    """
    scan_id_value = str(int(time.time() * 10000)) + get_random_str(2)
    if ports is None:
        sql = "INSERT INTO `flask_scan`.host_scan (scan_id, userid, byway, hosts, ErrorCode) " \
              "VALUE (?,?,1,?,?)"
        data = (scan_id_value, user_id, hosts, errorcode)
    else:
        sql = "INSERT INTO `flask_scan`.ports_scan (scan_id, userid, byway, hosts, ports, ErrorCode) " \
              "VALUE (?,?,1,?,?,?)"
        data = (scan_id_value, user_id, hosts, ports, errorcode)
    if sql_run1(sql=sql, data=data) == INSERT_SUCCESSFULLY:
        return True
    else:
        return False
