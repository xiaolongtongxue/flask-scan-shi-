"""
@File    ：Login.py
@Author  ：TXK
@Date    ：2022/10/22 9:49 
"""
# -*- coding: UTF-8 -*-
from bean.static import *
from dao.Connector import sql_run2
from util.Encode_Decode.Base import base64_decode
from util.Encode_Decode.Hash_Encode import hash_to_32


# 所有可能返回的错误内容
# USERNAME_NOT_EXIST = 202012     # 登陆时发现用户名不存在
# PASSWD_ERROR = 202013           # 登陆时密码输入错误
def login_sql(username: str, passwd_base: str, random: str):
    """
    注册账户用的函数
    :param username:  用户输入的用户名（明文）
    :param passwd_base:  用户输入的密码（经过加随机数混淆编码过了的）
    :param random:  前端生成的随机字符串
    :return: 列表第0 个元素为用户id，第1个元素为用户的等级
    """
    id_value = get_id(username=username)
    if id_value is None:
        return USERNAME_NOT_EXIST
    sql = "SELECT level FROM `flask_scan`.`users` WHERE username=? and passwd=?;"
    passwd = base64_decode(passwd_base)[0:-RAN_TOKEN_LEN]
    dump = sql_run2(sql=sql, data=(username, hash_to_32(id_value + passwd)))
    if len(dump) != 1:
        return PASSWD_ERROR
    return [id_value, dump[0][0]]


def get_id(username: str):
    sql = "SELECT id FROM `flask_scan`.`users` WHERE username=?;"
    try:
        return sql_run2(sql=sql, data=(username,))[0][0]
    except IndexError:
        return None
