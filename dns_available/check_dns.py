#encoding=utf-8  
"""
测试单个ip使用
"""
import sys
import socket
import random
import select
from DNS import Lib
from DNS import Type
from DNS import Class
from DNS import Opcode
import operator
import MySQLdb
import time

def check_ip(ip):
    """
    验证可以对外提供服务的DNS的ip，并将结果存入数据库
    """

    result = []                #结果初始化

    DPORT = 53                      #默认端口是53
    tid = random.randint(0,65535)   #tid为随机数
    opcode = Opcode.QUERY           #标准查询
    qtype = Type.A                  #查询类型为A
    qclass = Class.IN               #查询类IN
    rd = 1                          #期望递归查询

    domain_list = ['www.baidu.com','www.sina.com','www.163.com','www.ifeng.com','www.hitwh.edu.cn'] # 要查询的域名

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)             #建立一个UDP套接字（SOCK_DGRAM，代表UDP，AF_INET表示IPv4）
    except socket.error,msg:
        print "无法创建socket.Error code:" +str(msg[0])+',Error message:'+msg[1]    #error
        sys.exit(1)
    source_port = random.randint(1024, 65535) #windows不是65535                #随机port
    s.bind(('', source_port))  #绑定，检测所有接口
   
    for domain in domain_list:
        m = Lib.Mpacker()
        m.addHeader(tid, 0, opcode, 0, 0, rd, 0, 0, 0, 1, 0, 0, 0)
        m.addQuestion(domain,qtype,qclass)
                
        request = m.getbuf()
        try:
            s.sendto(request,(ip, DPORT))
            print 'domain: ',domain," send to Dns server:",ip
        except socket.error,reason:
            print  reason
            continue
                                      
        '''循环接收收到的返回header'''
    while 1:
        try:
            r,w,e = select.select([s], [], [],7)
            if not (r or w or e):
            
                break
            (data,addr) = s.recvfrom(65535)
            u = Lib.Munpacker(data)
            r = Lib.DnsResult(u,{})
            print r.header
            print r.answers
            if r.header['status'] == 'NOERROR':

                result.append({'domain' : r.questions[0]['qname'],'ip' : addr[0] ,'domain_info':'yes'})
                print r.questions[0]['qname'] + '\t' + addr[0] + ' success'
            else:
                if len(r.questions) != 0:
                    result.append({'domain' : r.questions[0]['qname'],'ip' : addr[0],'domain_info':'failed'})
                    print r.questions[0]['qname'] + '\t' + addr[0] + ' failed'
                else:
                    print 'questions is wrong'
        except socket.error, reason:
            print reason
            continue

    for test in result:
        print test

    s.close()  #关闭socket

def main():
    """
    测试函数
    """
    ip = '106.127.110.36'
    check_ip(ip)

if __name__ == "__main__":

    main()