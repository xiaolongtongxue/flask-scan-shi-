"""
@File    ：Base.py
@Author  ：TXK
@Date    ：2022/10/21 17:19 
"""
# -*- coding: UTF-8 -*-
import base64


def base64_encode(string: str):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')


def base64_decode(string: str):
    return base64.b64decode(string.encode('utf-8')).decode('utf-8')
