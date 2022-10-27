"""
@File    ：Select_By.py
@Author  ：TXK
@Date    ：2022/10/26 10:51 
"""
# -*- coding: UTF-8 -*-
from dao.Connector import sql_run2


def by_something_host(user_id: str, scan_id: str = None, byway: str = None, hosts_: str = None, errorcode: str = None):
    sql = "SELECT * FROM `flask_scan`.`host_scan` WHERE userid=?"
    data = (user_id,)
    if scan_id is not None:
        sql += " AND scan_id=?"
        data += (scan_id,)
    if byway is not None:
        sql += " AND byway=?"
        data += (byway,)
    if hosts_ is not None:
        sql += " AND hosts like ?"
        data += ("%" + hosts_ + "%",)
    if errorcode is not None:
        sql += " AND errorcode=?"
        data += (errorcode,)
    sql += " ORDER BY scan_time DESC"
    return sql_run2(sql=sql, data=data)


def by_something_port(user_id: str, scan_id: str = None, byway: str = None, hosts_: str = None, errorcode: str = None,
                      ports: str = None):
    sql = "SELECT * FROM `flask_scan`.`ports_scan` WHERE userid=?"
    data = (user_id,)
    if scan_id is not None:
        sql += " AND scan_id=?"
        data += (scan_id,)
    if byway is not None:
        sql += " AND byway=?"
        data += (byway,)
    if hosts_ is not None:
        sql += " AND hosts like ?"
        data += ("%" + hosts_ + "%",)
    if ports is not None:
        sql += " AND ports like ?"
        data += (ports,)
    if errorcode is not None:
        sql += " AND errorcode=?"
        data += (errorcode,)
    sql += " ORDER BY scan_time DESC"
    return sql_run2(sql=sql, data=data)


if __name__ == '__main__':
    # print(str(by_byway_host("2")[0][0]))
    print(by_something_host(user_id="16664091330218", byway="1"))
    print(by_something_port(user_id="16664091330218", ports="8"))
    """
    [(datetime.datetime(2022, 10, 26, 10, 33, 3), '16667515837419VZ', '16664091330218', 1, 'admin', None, 107019)]
    [(datetime.datetime(2022, 10, 25, 10, 21, 44), '16666644175448ES', '16664091330218', 1, '192.168.110.131,192.168.110.1', '80-22', None, 107018), (datetime.datetime(2022, 10, 25, 10, 23, 48), '16666646288060iH', '16664091330218', 1, '192.168.110.131,192.168.110.1', '22,80', "{'192.168.110.1': False, '192.168.110.131': {22: False, 80: False}}", None)]
    """
