#encoding:utf-8  
"""
优化代码，功能合理分类
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

UPDATE_NUM = 50  #数据库更新频率

conn=MySQLdb.Connection(host='localhost',user='root',passwd='cynztt',db='dns_detect',charset='utf8')
cursor = conn.cursor()


def get_ip():
    """
    获得所要查询的DNS的ip
    """

    data = []
    cursor = conn.cursor()
    sql = 'SELECT ip from dns_available_copy WHERE visit_time is NULL or visit_time = "" '
    try:
        cursor.execute(sql)
    except:
        print "Error: unable to fecth data"
        sys.exit(1)

    data = cursor.fetchall()
    return data              #返回结果


def check_ip(ip_list):
    """
    验证可以对外提供服务的DNS的ip，并将结果存入数据库
    """

    result = []                #结果初始化

    if not ip_list :           #list is empty
        print 'ip is empty,nothing to check'
        return result
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

    count = 0
    rowcount = len(ip_list)
    result = []             #得到的结果
    result_ip = []
    result_diffrences = []
    ip_source = []

    while count * 20 < rowcount:  
        ips = ip_list[count * 20 : (count + 1) * 20]

        result = []             #得到的结果
        result_ip = []
        result_diffrences = []
        ip_source = []
        
        """发送验证的DNS的ip"""
        for domain in domain_list:
        # for ip in ips:
        #     ip_source.append(ip[0])

            '''循环发送需要解析的domain name'''         
            # for domain in domain_list:
            for ip in ips:
                ip_source.append(ip[0])
                try:
                    m = Lib.Mpacker()
                    m.addHeader(tid, 0, opcode, 0, 0, rd, 0, 0, 0, 1, 0, 0, 0)
                    m.addQuestion(domain,qtype,qclass)
                
                    request = m.getbuf()
                except:
                    print 'request wrong'
                    time.sleep(10)
                    continue

                try:
                    s.sendto(request,(ip[0].strip(), DPORT))
                    print 'domain: ',domain," send to Dns server:",ip[0]
                except socket.error,reason:
                    print  reason
                    continue
                                      
        '''循环接收收到的返回header'''
        while 1:
            try:
                r,w,e = select.select([s], [], [],7)
                if not (r or w or e):
                    #s.close()
                    break
                (data,addr) = s.recvfrom(65535)
                u = Lib.Munpacker(data)
                r = Lib.DnsResult(u,{})
                    
                if r.header['status'] == 'NOERROR':

                    result.append({'domain' : r.questions[0]['qname'],'ip' : addr[0] ,'domain_info':'yes'})
                    result_ip.append(addr[0])    
                    print r.questions[0]['qname'] + '\t' + addr[0] + ' success'
                else:
                    if len(r.questions) != 0:
                        result.append({'domain' : r.questions[0]['qname'],'ip' : addr[0],'domain_info':'failed'})
                        result_ip.append(addr[0])
                        print r.questions[0]['qname'] + '\t' + addr[0] + ' failed'
                    else:
                        print 'questions is wrong'
            except socket.error, reason:
                print reason
                continue

        result_diffrences = list(set(ip_source).difference(set(result_ip))) #得到没有响应的dns的ip
        result2sql(result)                                                  #将有响应的dns结果存入数据库
        result_timeout(result_diffrences)                                   #将无响应的dns访问时间存入数据库
        count = count + 1
    s.close()  #关闭socket


def result2sql(results):
    """
    结果存入数据库
    """
    if not results:
        print 'result is empty'
        return
    current_time = time.strftime("%Y-%m-%d %X",time.localtime())
    try:
        for result in results:
            if result['domain'] == 'www.baidu.com':
                sql = ' UPDATE dns_available_copy SET baidu = "%s",visit_time = "%s" WHERE ip = "%s" ' % (result['domain_info'],current_time,result['ip'])
                cursor.execute(sql)
                
            elif result['domain'] == 'www.ifeng.com':
                sql = ' UPDATE dns_available_copy SET ifeng = "%s",visit_time = "%s" WHERE ip = "%s" '  % (result['domain_info'],current_time,result['ip'])
                cursor.execute(sql)
                
            elif result['domain'] == 'www.163.com':
                sql = ' UPDATE dns_available_copy SET wangyi = "%s",visit_time = "%s" WHERE ip = "%s" ' % (result['domain_info'],current_time,result['ip'])
                cursor.execute(sql)
                
            elif result['domain'] == 'www.hitwh.edu.cn':
                sql = ' UPDATE dns_available_copy SET hitwh = "%s",visit_time = "%s" WHERE ip = "%s" ' % (result['domain_info'],current_time,result['ip'])
                cursor.execute(sql)
                
            else:
                sql = ' UPDATE dns_available_copy SET sina = "%s",visit_time = "%s" WHERE ip = "%s" ' % (result['domain_info'],current_time,result['ip'])
                cursor.execute(sql)
        conn.commit()
    except:
        print 'Update failed'
        conn.rollback()


def result_timeout(result_diffrences):
    """
    无响应的dns的访问时间存入数据库
    """
    if not result_diffrences:
        print 'result_timeout is empty'
        return
    current_time = time.strftime("%Y-%m-%d %X",time.localtime())
    try:
        for result in result_diffrences:
            print result + ' is timeout'
            sql = ' UPDATE dns_available_copy SET visit_time = "%s" WHERE ip = "%s" ' % (current_time,result)
            cursor.execute(sql)
        conn.commit()
    except:
        print 'result_difference update failed'
        conn.rollback()


def main():
    """
    测试函数
    """

    ip_list = []       #查询集
    result_list = []   #结果集

    ip_list = get_ip()
    check_ip(ip_list)
    cursor.close()     #关闭cursor
    conn.close()       #关闭conn


if __name__ == "__main__":

    main()