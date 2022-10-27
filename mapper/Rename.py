"""
@File    ：Rename.py
@Author  ：TXK
@Date    ：2022/10/27 13:50 
"""
# -*- coding: UTF-8 -*-
from bean.static import *
from dao.Connector import sql_run1
from util.Encode_Decode.Base import base64_decode
from util.Encode_Decode.Hash_Encode import hash_to_32


def rename_passwd(user_id: str, new_name: str = None, passwd_1: str = None, passwd_2: str = None):
    end = []
    if new_name != "":
        sql1 = "UPDATE `flask_scan`.`users` SET username=? WHERE id='" + user_id + "';"
        data = (new_name,)
        if sql_run1(sql=sql1, data=data):
            end.append(True)
        else:
            end.append(False)
    else:
        end.append(True)
    if base64_decode(passwd_1) != "" and passwd_1 == passwd_2:
        passwd_1 = base64_decode(passwd_1)
        sql1 = "UPDATE `flask_scan`.`users` SET passwd=? WHERE id='" + user_id + "';"
        data = (hash_to_32(user_id + passwd_1),)
        if sql_run1(sql=sql1, data=data):
            end.append(True)
        else:
            end.append(False)
    return end
