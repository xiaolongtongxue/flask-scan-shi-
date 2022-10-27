"""
@File    ：MyThread.py
@Author  ：TXK
@Date    ：2022/10/19 14:11 
"""
# -*- coding: UTF-8 -*-
import threading

class MyThread(threading.Thread):
    def __init__(self, func, args, name=''):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args
        self.result = self.func(*self.args)

    def get_result(self):
        try:
            return self.result
        except Exception:
            return None

