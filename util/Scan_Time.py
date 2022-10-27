"""
@File    ：Scan_Time.py
@Author  ：TXK
@Date    ：2022/10/24 17:02 
"""
# -*- coding: UTF-8 -*-
from bean.MyThread import MyThread
from mapper.scapy.s_host_scan_alive import s_host_scan
from mapper.scapy.s_port_scan_alive import s_port_scan
from mapper.nmap.n_host_alive import n_host_scan_sP
from mapper.nmap.n_port_alive import n_port_scan_sV
from mapper.scapy.Rem_Scapy import rem_scapy, rem_scapy_error
from mapper.nmap.Rem_Nmap import rem_nmap


def scapy_scan_host(userid: str, hosts: str, dns: bool = False):
    end = s_host_scan(hosts=hosts, dns=dns)
    if isinstance(end, int):
        err_status = rem_scapy_error(user_id=userid, hosts=hosts, errorcode=end)
        if err_status:
            return
        else:
            print("error")
            # 补一个写文件的东西记录数据库错误。口令：7Ez7FbxEhHJy87XsDDhKk4udg8RXEG4Phwt7E
            return
    ip_list = []
    ending = ""
    for ip in end:
        ip_list.append(ip)
        ending += ip + ":"
        if not end[ip]:
            ending += "0"
    # print(end)
    # print(str(end))
    end = str(end)
    rem_status = rem_scapy(user_id=userid, hosts=hosts, end=end)
    if rem_status:
        return
    else:
        print("error")
        # 补一个写文件的东西记录数据库错误。口令：7Ez7FbxEhHJy87XsDDhKk4udg8RXEG4Phwt7E
        return


def scapy_scan_ports(userid: str, hosts: str, ports: str, dns: bool = False):
    end1 = s_host_scan(hosts=hosts, dns=dns)
    if isinstance(end1, int):
        err_status = rem_scapy_error(user_id=userid, hosts=hosts, errorcode=end1, ports=ports)
        if err_status:
            return
        else:
            print("error")
            # 补一个写文件的东西记录数据库错误。口令：7Ez7FbxEhHJy87XsDDhKk4udg8RXEG4Phwt7E
            return
    target_list = []
    end = {}
    for ip in end1:
        if not end1[ip]:
            end.update({ip: False})
        else:
            target_list.append(ip)

    for ip in target_list:
        t = MyThread(s_port_scan, (ip, None, ports), s_port_scan.__name__)
        t.start()
        if isinstance(t.get_result(), int):
            err_status = rem_scapy_error(user_id=userid, hosts=hosts, errorcode=t.get_result(), ports=ports)
            if err_status:
                return
            else:
                print("ports-error")
                # 补一个写文件的东西记录数据库错误。口令：7Ez7FbxEhHJy87XsDDhKk4udg8RXEG4Phwt7E
                return
        end.update({ip: t.get_result()})
    end = str(end)
    rem_status = rem_scapy(user_id=userid, hosts=hosts, ports=ports, end=end)
    if rem_status:
        return
    else:
        print("error")
        # 补一个写文件的东西记录数据库错误。口令：7Ez7FbxEhHJy87XsDDhKk4udg8RXEG4Phwt7E
        return


def nmap_scan_hosts(userid: str, hosts: str):
    try:
        end = str(n_host_scan_sP(hosts=hosts))
    except Exception as e:
        end = str({hosts: e})
    rem_status = rem_nmap(user_id=userid, hosts=hosts, end=end)
    if rem_status:
        return
    else:
        print("error")
        # 补一个写文件的东西记录数据库错误。口令：7Ez7FbxEhHJy87XsDDhKk4udg8RXEG4Phwt7E
        return


def nmap_scan_ports(userid: str, hosts: str, ports: str, scan_type: str = "-sV"):
    try:
        end = str(n_port_scan_sV(hosts=hosts, ports=ports, scan_type=scan_type))
    except Exception as e:
        end = str({hosts: e})
    rem_status = rem_nmap(user_id=userid, hosts=hosts, end=end, ports=ports)
    if rem_status:
        return
    else:
        print("error")
        # 补一个写文件的东西记录数据库错误。口令：7Ez7FbxEhHJy87XsDDhKk4udg8RXEG4Phwt7E
        return


if __name__ == '__main__':
    # scapy 系列测试
    '''
    if True:
        # scapy_scan_host(hosts="192.168.110.131,192.168.110.1", dns=False, userid="16664091330218")
        """
        {
            '192.168.110.131': {
                'end': True, 
                'hwsrc': '00:0c:29:31:91:67', 
                'psrc': '192.168.110.131', 
                'hwdst': '00:50:56:c0:00:02', 
                'pdst': '192.168.110.1'
            }, 
            '192.168.110.1': False
        }
        """
        scapy_scan_ports(hosts="192.168.110.131,192.168.110.1", ports="22,80", dns=False, userid="16664091330218")
        """
        {
            '192.168.110.1': False, 
            '192.168.110.131': {
                22: False, 
                80: False
            }
        }
        """
        pass
    '''
    # nmap 系列测试
    # nmap_scan_hosts(hosts="127.0.0.1，192.168.1.55", userid="16664091330218")
    nmap_scan_ports(hosts="127.0.0.1,192.168.1.55", userid="16664091330218", ports="3306", scan_type="-sS")
    """
    {'127.0.0.1': True, '192.168.1.55': False}
    """

    pass
