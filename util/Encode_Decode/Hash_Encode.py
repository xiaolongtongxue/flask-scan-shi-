"""
@File    ：Hash_Encode.py
@Author  ：TXK
@Date    ：2022/10/21 9:13 
"""
# -*- coding: UTF-8 -*-
import hashlib

def hash_to_32(key: str):
    input_name = hashlib.md5()
    input_name.update(key.encode("utf-8"))
    return input_name.hexdigest()
