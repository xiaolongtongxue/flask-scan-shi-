"""
@File    ：Random_Str.py
@Author  ：TXK
@Date    ：2022/10/21 13:53 
"""
# -*- coding: UTF-8 -*-
import random


def get_random_str(length: int):
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length_ = len(base_str) - 1
    for i in range(length):
        random_str += base_str[random.randint(0, length_)]
    return random_str