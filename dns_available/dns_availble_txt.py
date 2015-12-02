#encoding=utf-8  
"""
version:0.2
输入:txt格式文件
输出:txt格式文件

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

class DomainToIp:
    
    def __init__(self,DHOST='114.114.114.114'):
        '''
        初始化类DomainToIp，连接数据库，DNS服务器ip地址可以更改，默认为114.114.114.114
        '''
        
        self.DHOST = DHOST                   #DNS 服务器的地址
        self.DPORT = 53                      #默认端口是53
        self.tid = random.randint(0,65535)   #tid为随机数
        self.opcode = Opcode.QUERY           #标准查询

        self.qtype = Type.A                  #查询类型为A
        self.qclass = Class.IN               #查询类IN
        self.rd = 1                          #期望递归查询

        #要查询的域名
        self.domain_list = ['www.baidu.com','www.sina.com','www.163.com','www.ifeng.com','www.hitwh.edu.cn']
        
        
        
    def send_domain_receive_ip(self):

        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            #建立一个UDP套接字（SOCK_DGRAM，代表UDP，AF_INET表示IPv4）
        except socket.error,msg:
            print "无法创建socket.Error code:" +str(msg[0])+',Error message:'+msg[1]    #error
            sys.exit(1)
        source_port = random.randint(1024, 65535)                           #随机port
        s.bind(('', source_port))                                                                                                         #绑定，检测所有接口
        
        
        domain_source = []       #发送的domain数量
        domain_result = []       #接收到的domain数量，这两个变量主要用来判断丢包情况

        '''循环发送需要解析的domain name'''         
        for domain in self.domain_list:
            
            #domain_source.append(domain)
            
            m = Lib.Mpacker()
            m.addHeader(self.tid, 0, self.opcode, 0, 0, self.rd, 0, 0, 0, 1, 0, 0, 0)
            m.addQuestion(domain,self.qtype,self.qclass)
            request = m.getbuf()
            try:
        
                s.sendto(request,(self.DHOST, self.DPORT))
                print 'domain: ',domain," send to Dns server:",self.DHOST
            except socket.error,reason:
                print  reason
            
        result=[]             #得到的结果
        result_servfail = []  #返回的servfail结果

        '''循环接收收到的返回header'''

        while True:
            try:
                r,w,e = select.select([s], [], [],5)
                if not (r or w or e):
                    break
                (data,addr) = s.recvfrom(65535)
                u = Lib.Munpacker(data)
                r = Lib.DnsResult(u,{})
            
                if r.header['status'] == 'NOERROR':

                    result.append({'domain' : r.questions[0]['qname'],'domain_info':'yes'})
                    domain_result.append(r.questions[0]['qname'])
                    print r.questions[0]['qname'] + '\t' + self.DHOST + ' success'
                else:
                    if len(r.questions) != 0:
                        result.append({'domain' : r.questions[0]['qname'],'domain_info':'failed'})
                        domain_result.append(r.questions[0]['qname'])
                        print r.questions[0]['qname'] + '\t' + self.DHOST + ' failed'
                    else:
                        print 'questions is wrong'
            except socket.error, reason:
                print reason
                continue
            

        result_diffrences = list(set(self.domain_list).difference(set(domain_result)))

        # 设置超时标识
        for result_diffrence in result_diffrences:
            result.append({'domain': result_diffrence,'domain_info': 'timeout'})
        sorted_result = sorted(result, key=operator.itemgetter('domain'))
        s.close()
        return sorted_result
        
        
if __name__ == "__main__":

    ip_list = []
    fr = open('dnsip.txt',"r")
    fw = open('dns_results.txt',"a")
    
    ip_list = fr.readlines()

    for ip in ip_list:
        str_write = ''
        domain = DomainToIp(ip.strip())
        results = domain.send_domain_receive_ip()
        print results
        str_write = ip.strip() + '\t' + results[0]['domain_info'] + '\t' + results[1]['domain_info']+'\t'+results[2]['domain_info']+'\t'+results[3]['domain_info']+'\t'+results[4]['domain_info']+'\n'
        fw.write(str_write)
    
    fr.close()
    fw.close()