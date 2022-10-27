"""
@File    ：Register.py
@Author  ：TXK
@Date    ：2022/10/21 9:38 
"""
# -*- coding: UTF-8 -*-
import time

from bean.static import *
from dao.Connector import sql_run1
from util.Encode_Decode.Base import base64_decode
from util.Encode_Decode.Hash_Encode import hash_to_32


def register_sql(username: str, passwd_base: str, random: str):
    """
    注册账户用的函数
    :param username:  用户输入的用户名（明文）
    :param passwd_base:  用户输入的密码（经过加随机数混淆编码过了的）
    :param random:  前端生成的随机字符串
    :return:
    """
    id_value = str(int(time.time() * 10000))
    passwd = base64_decode(passwd_base)[0:-RAN_TOKEN_LEN]
    sql = "INSERT INTO `flask_scan`.`users` (id, username, passwd) VALUES (?, ?, ?);"
    if sql_run1(sql=sql, data=(id_value, username, hash_to_32(id_value + passwd))) == INSERT_SUCCESSFULLY:
        print("OK")
        return True
    else:
        return False

# if __name__ == '__main__':
#     register_sql("test", "YWRtaW5wNlB6MlVkaTByWWdNRkY=", "p6Pz2Udi0rYgMFF")
