#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@author: xiao cai niao
'''
from lib.log import Logging
import socket,psutil,dpkt
from dpkt.compat import compat_ord
import time,threading,struct
from clickhouse_driver import connect
import json

class Op_packet:
    def __init__(self,**kwargs):
        self.kwargs = kwargs
        self.queue = kwargs['queue']
        self._type = kwargs['_type']

        self.mysql_user = kwargs['user'] if 'user' in kwargs else None
        self.mysql_passwd = kwargs['passwd'] if 'passwd' in kwargs else None
        if self.mysql_user:
            if self.mysql_passwd:
                pass
            else:
                print('Mysql connection information needs to be set at the same time')
                import sys
                sys.exit()

        self.all_session_users = {}
        self.get_user_list = {}

    def __get_netcard(self):
        '''get ip address'''
        info = psutil.net_if_addrs()
        for k, v in info.items():
            for item in v:
                if item[0] == 2 and not item[1] == '127.0.0.1' and ':' not in k:
                    netcard_info = item[1]
        return netcard_info

    def mac_addr(self,address):
        """Convert a MAC address to a readable/printable string

           Args:
               address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
           Returns:
               str: Printable/readable MAC address
        """
        return ':'.join('%02x' % compat_ord(b) for b in address)

    def inet_to_str(self,inet):
        """Convert inet object to a string

            Args:
                inet (inet struct): inet network address
            Returns:
                str: Printable/readable IP address
        """
        # First try ipv4 and then ipv6
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)


    def Unpacking(self,data):
        """
        unpack packet
        :return:
        """
        self.offset = 8          #跳过头部的*3\r\n$4\r\n
        s_end = self.find_r(data)
        self.command = data[self.offset:s_end].decode("utf8", "ignore")
        self.offset = s_end + 2
        # self.seek_num = 0
        while 1:
            if self.check_payload():
                return
            if self.seek_tmp(data):
                self.get_string(data)
            else:
                return


    def get_string(self,data):
        s_end = self.find_r(data)
        self.command = self.command + ' ' + data[self.offset:s_end].decode("utf8", "ignore")
        self.offset = s_end + 2

    def seek_tmp(self, data):
        # self.seek_num += 1
        # if self.seek_num >= 10:
        #     print(self.offset, self.payload)
        if self.check_payload():
            return None
        elif self.check_a(data):
            self.find_n(data)
            return self.seek_tmp(data)
        else:
            return True

    def find_n(self, data):
        s_end = data.find(b'\n', self.offset)
        self.offset = s_end + 1

    def find_r(self, data):
        return data.find(b'\r', self.offset)

    def check_a(self, data):
        if data[self.offset] == 36:
            return True
        return None

    def check_payload(self):
        if self.offset + 2 >= self.payload:
            return True
        elif self.offset < 8:
            return True
        return None

    def GetSession(self,srchost,srcport,dsthost,dstport):
        '''
        获取session key, 并检查是否为client请求包，如果为server返回包将直接抛弃
        :param srchost:
        :param srcport:
        :param dsthost:
        :param dstport:
        :return:
        '''
        if self._type == 'src':
            if srchost == self._ip:
                '''client packet'''
                session = [srchost,srcport,dsthost,dstport]
                return session,True
            else:
                '''server response'''
                return None,None

        elif self._type == 'des':
            if srchost == self._ip:
                '''server response'''
                return None,None
            else:
                '''client packet'''
                session = [srchost, srcport,dsthost, dstport]
                return session,True

    def an_packet(self):
        self._ip = self.__get_netcard()
        self._logging = Logging()
        self.command_list = []
        self.command_list_len = 0
        while 1:
            if not self.queue.empty():
                buf,_cur_time = self.queue.get()
                eth = dpkt.ethernet.Ethernet(buf)

                if not isinstance(eth.data, dpkt.ip.IP):
                    self._logging.error(msg='Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
                    continue

                ip = eth.data

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    src_host,dst_host = self.inet_to_str(ip.src),self.inet_to_str(ip.dst)
                    session, session_status = self.GetSession(src_host,tcp.sport,dst_host, tcp.dport)
                    if session_status:
                        self.payload = len(tcp.data)
                        if self.payload <= 8 and self.payload >= 4194304:   # 抛弃小于8字节和大于4m的数据包
                            continue
                        self.Unpacking(data=tcp.data)
                        if len(self.command) > 0:
                            jsons = {'source_host': session[0], 'source_port': session[1], 'destination_host': session[2],
                                     'destination_port': session[3],
                                     'command': self.command, 'event_time': int(_cur_time)}
                            self.command_list.append(jsons)
                            self.command_list_len += 1
                            self.insert_ck()
                            #self._logging.info(msg=json.dumps(jsons))
            else:
                time.sleep(0.01)

    def insert_ck(self):
        if self.command_list_len >=1000:
            conn = connect('clickhouse://10.0.0.253')
            cursor = conn.cursor()
            cursor.executemany('insert into redis_audit.redis_audit_info(source_host,source_port,destination_host,destination_port,command,event_date)',self.command_list)
            self.command_list_len = 0
            self.command_list = []
