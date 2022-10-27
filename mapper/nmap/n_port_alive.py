"""
@File    ：n_port_alive.py
@Author  ：TXK
@Date    ：2022/10/22 16:45 
"""
# -*- coding: UTF-8 -*-
import nmap  # 导入模块

from util.Get_Hosts_List import to_nmap_get_hosts


def n_port_scan_sV(hosts: str, ports: str = None, scan_type: str = "-sV"):
    hosts = to_nmap_get_hosts(hosts=hosts)
    # print(hosts)
    # print(hosts_list)
    # print(hosts_list[0:-1].split(" "))
    nm = nmap.PortScanner()
    nm.scan(hosts=hosts, ports=ports, arguments=scan_type)
    # print(nm.all_hosts())

    end = {}

    if hosts[-1] == " ":
        end_ = hosts[0:-1]
    else:
        end_ = hosts

    for host in end_.split(" "):
        end_ = {"model": scan_type}
        if host in nm.all_hosts():
            end_.update(dict(nm[host]))
            end.update({host: end_})
        else:
            end.update({host: False})

    # print(end)

    # for host in nm.all_hosts():
    #     end_ = {"model": scan_type}
    #     end_.update(dict(nm[host]))
    #     end.update({host: end_})
    return end


"""
DEMO:
[
  {
    "hostnames": [
      {
        "name": "localhost",
        "type": "PTR"
      }
    ],
    "addresses": {
      "ipv4": "127.0.0.1"
    },
    "vendor": {},
    "status": {
      "state": "up",
      "reason": "localhost-response"
    },
    "tcp": {
      135: {
        "state": "open",
        "reason": "syn-ack",
        "name": "msrpc",
        "product": "Microsoft Windows RPC",
        "version": "",
        "extrainfo": "",
        "conf": "10",
        "cpe": "cpe:/o:microsoft:windows"
      },
      445: {
        "state": "open",
        "reason": "syn-ack",
        "name": "microsoft-ds",
        "product": "",
        "version": "",
        "extrainfo": "",
        "conf": "3",
        "cpe": ""
      },
      808: {
        "state": "open",
        "reason": "syn-ack",
        "name": "mc-nmf",
        "product": ".NET Message Framing",
        "version": "",
        "extrainfo": "",
        "conf": "10",
        "cpe": "cpe:/o:microsoft:windows"
      },
      902: {
        "state": "open",
        "reason": "syn-ack",
        "name": "vmware-auth",
        "product": "VMware Authentication Daemon",
        "version": "1.10",
        "extrainfo": "Uses VNC, SOAP",
        "conf": "10",
        "cpe": ""
      },
      912: {
        "state": "open",
        "reason": "syn-ack",
        "name": "vmware-auth",
        "product": "VMware Authentication Daemon",
        "version": "1.0",
        "extrainfo": "Uses VNC, SOAP",
        "conf": "10",
        "cpe": ""
      },
      2869: {
        "state": "open",
        "reason": "syn-ack",
        "name": "http",
        "product": "Microsoft HTTPAPI httpd",
        "version": "2.0",
        "extrainfo": "SSDP/UPnP",
        "conf": "10",
        "cpe": "cpe:/o:microsoft:windows"
      },
      3306: {
        "state": "open",
        "reason": "syn-ack",
        "name": "mysql",
        "product": "MySQL",
        "version": "5.7.17-log",
        "extrainfo": "",
        "conf": "10",
        "cpe": "cpe:/a:mysql:mysql:5.7.17-log"
      },
      9001: {
        "state": "open",
        "reason": "syn-ack",
        "name": "http",
        "product": "Microsoft HTTPAPI httpd",
        "version": "2.0",
        "extrainfo": "SSDP/UPnP",
        "conf": "10",
        "cpe": "cpe:/o:microsoft:windows"
      },
      10000: {
        "state": "open",
        "reason": "syn-ack",
        "name": "snet-sensor-mgmt",
        "product": "",
        "version": "",
        "extrainfo": "",
        "conf": "3",
        "cpe": ""
      }
    }
  },
  {
    "hostnames": [
      {
        "name": "",
        "type": ""
      }
    ],
    "addresses": {
      "ipv4": "192.168.1.1",
      "mac": "18:F2:2C:E6:1D:C7"
    },
    "vendor": {},
    "status": {
      "state": "up",
      "reason": "arp-response"
    },
    "tcp": {
      80: {
        "state": "open",
        "reason": "syn-ack",
        "name": "http",
        "product": "",
        "version": "",
        "extrainfo": "",
        "conf": "10",
        "cpe": ""
      },
      1900: {
        "state": "open",
        "reason": "syn-ack",
        "name": "upnp",
        "product": "",
        "version": "",
        "extrainfo": "",
        "conf": "3",
        "cpe": ""
      }
    }
  }
]
"""

if __name__ == '__main__':
    print(n_port_scan_sV(hosts="127.0.0.1,192.168.1.55,192.168.1.106", scan_type="-sV123", ports="3306"))

# def n_port_scan():
#     nm = nmap.PortScanner()
#     nm.scan(hosts='192.168.1.0', ports='1888,3306', arguments="-sV")
#     # print(nm.all_hosts())
#
#     end = []
#
#     for host in nm.all_hosts():
#         end.append(dict(nm[host]))
#         # print('---------------------------------------------------------')
#         # print('Host : %s (%s)' % (host, nm[host].hostname()))
#         # print('State : %s' % nm[host].state())
#         #
#         # print(type(nm[host]))
#         # print(dict(nm[host]))
#         # print(type(dict(nm[host])))
#         #
#         #
#         # for proto in nm[host].all_protocols():
#         #     print('-----------------------------------------------------')
#         #     print('protocol : %s' % proto)
#         #     lport = nm[host][proto].keys()
#         #     print(lport)
#         #     for port in lport:
#         #         # print(nm[host][proto][port])
#         #         # {
#         #         #   'state': 'open',
#         #         #   'reason': 'syn-ack',
#         #         #   'name': 'msrpc',
#         #         #   'product': 'Microsoft Windows RPC',
#         #         #   'version': '',
#         #         #   'extrainfo': '',
#         #         #   'conf': '10',
#         #         #   'cpe': 'cpe:/o:microsoft:windows'
#         #         # }
#         #         print(type(nm[host][proto][port]))
#         #         print("port:" + str(port), end="\t")
#         #         for i in nm[host][proto][port]:
#         #             print(i, end=":")
#         #             print(nm[host][proto][port][i], end="\t")
#         #         print()
#         #         # print('port : %s\tstate : %s\t version: %s' % (
#         #         #     port, nm[host][proto][port]['state'], nm[host][proto][port]['version']
#         #         # ))
#     return end
