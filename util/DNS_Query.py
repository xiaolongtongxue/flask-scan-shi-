"""
@File    ：DNS_Query.py
@Author  ：TXK
@Date    ：2022/10/19 17:10 
"""
# -*- coding: UTF-8 -*-
import dns.resolver
from bean.static import *


def dns_query(host: str):
    try:
        ans = dns.resolver.resolve(host, "A")
    except Exception:
        return DNS_ERROR
    address = []
    for i in ans.response.answer:
        for j in i.items:
            address.append(j.address)
            # if isinstance(j, dns.rdtypes.IN.A.A):
            #     print('\st2 %st1' % (j.address))
            # if isinstance(j, dns.rdtypes.ANY.CNAME.CNAME):
            #     print( 'CNAME: %st1' % (j))
    return address