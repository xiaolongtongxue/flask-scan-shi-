"""
@File    ：s_port_scan_alive.py
@Author  ：TXK
@Date    ：2022/10/16 13:43 
"""

# -*- coding: UTF-8 -*-
from scapy.layers.inet import *

from bean.static import *
from bean.MyThread import MyThread

# 本段中所有可能出现的错误代码：
# 1. VALUE_NUK_LOWERSIZE        出现了为负的端口号
# 2. VALUE_NUM_OVERSIZE         出现了超过65535的端口号
# 3. VALUE_NUM_ERROR            传入端口格式为 a-b 或 a1,a2,a3 时，字符串出现格式错误
# 4. VALUE_SIZE_ERROR           传入端口格式为 a-b 时，出现 a>b 的情况
# 5. NONE_VALUE                 传了个空
def s_port_scan(target: str = None, port: int = None, ports: str = None):
    if (port is None and ports is None) or target is None:
        return NONE_VALUE
    else:
        if ports is None:
            if port < 0:
                return VALUE_NUK_LOWERSIZE
            if port > 65535:
                return VALUE_NUM_OVERSIZE
            return scan_port1(target=target, port=port)
        else:
            if "-" in ports:
                try:
                    min, max = ports.split("-")
                    min, max = int(min), int(max)
                    if min < 0:
                        return VALUE_NUK_LOWERSIZE
                    if max > 65535:
                        return VALUE_NUM_OVERSIZE
                    if min > max:
                        return VALUE_SIZE_ERROR
                except ValueError:
                    return VALUE_NUM_ERROR
                ports = ""
                for i in range(min, max + 1):
                    ports += str(i) + ","
                ports = ports[:-1]
            else:
                for tmp in ports.split(","):
                    try:
                        tmp_n = int(tmp)
                        if tmp_n < 0:
                            return VALUE_NUK_LOWERSIZE
                        if tmp_n > 65535:
                            return VALUE_NUM_OVERSIZE
                    except ValueError:
                        return VALUE_NUM_ERROR
            return scan_portn(target=target, ports=list(map(int, ports.split(","))))


def scan_port1(target: str, port: int):
    ans = sr1(IP(dst=target) / TCP(dport=port, flags="S"), timeout=5, verbose=0)
    if ans is None:
        return {port: True}
    else:
        return {port: False}


def scan_portn(target: str, ports: list):
    end = {}
    for port in ports:
        t = MyThread(scan_port1, (target, port), scan_port1.__name__)
        t.start()
        end.update(t.get_result())
    return end


if __name__ == '__main__':
    End = s_port_scan(target="127.0.0.1", port=3306)
    print(End)
