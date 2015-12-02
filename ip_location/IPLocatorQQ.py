#! /usr/bin/python2.7
#encoding:utf-8

import socket,struct,sys
from mysql_connection import MysqlConnection

class IPLocator :
    def __init__( self, ipdbFile='QQWry/qqwry.dat' ):
        '''
        初始化类，数据格式为little-endian模式，需要转换
        '''
        self.ipdb = open( ipdbFile, "rb" )                                                  #只读二进制格式打开文件
        str = self.ipdb.read( 8 )                                                                    #文件前8个字节为文件头
        (self.firstIndex,self.lastIndex) = struct.unpack('II',str)         #得到索引区中的第一条索引记录和最后一条索引记录的偏移位置
        self.indexCount = (self.lastIndex - self.firstIndex)/7+1         #得到记录总数

    def getVersion(self):
        '''
        得到纯真ip地址库的版本号
        '''
        version = self.getIpAddr(0xffffff00L)   #纯真数据库中存储版本信息位置为：255.255.255.0
        return version
    def getIndexCount(self):
        '''
        得到数据记录总数
        '''
        print self.getVersion()," 记录总数: %d 条 "%(self.indexCount)     #输出版本号和记录总数

    def getAreaAddr(self,offset=0):
        if offset :
            self.ipdb.seek( offset )
        str = self.ipdb.read( 1 )
        (byte,) = struct.unpack('B',str)
        if byte == 0x01 or byte == 0x02:
            p = self.getLong3()
            if p:
                return self.getString( p )
            else:
                return ""
        else:
            self.ipdb.seek(-1,1)
            return self.getString( offset )

    def getAddr(self,offset,ip=0):
        self.ipdb.seek( offset + 4)
        countryAddr = ""
        areaAddr = ""
        str = self.ipdb.read( 1 )
        (byte,) = struct.unpack('B',str)
        if byte == 0x01:
            countryOffset = self.getLong3()
            self.ipdb.seek( countryOffset )
            str = self.ipdb.read( 1 )
            (b,) = struct.unpack('B',str)
            if b == 0x02:
                countryAddr = self.getString( self.getLong3() )
                self.ipdb.seek( countryOffset + 4 )
            else:
                countryAddr = self.getString( countryOffset )
            areaAddr = self.getAreaAddr()
        elif byte == 0x02:
            countryAddr = self.getString( self.getLong3() )
            areaAddr = self.getAreaAddr( offset + 8 )
        else:
            countryAddr = self.getString( offset + 4 )
            areaAddr = self.getAreaAddr()
        return countryAddr + " " + areaAddr

    def dump(self, first ,last ):
        if last > self.indexCount :
            last = self.indexCount
        for index in range(first,last):
            offset = self.firstIndex + index * 7
            self.ipdb.seek( offset )
            buf = self.ipdb.read( 7 )
            (ip,of1,of2) = struct.unpack("IHB",buf)
            print "%d\t%s\t%s" %(index, self.ip2str(ip), \
                self.getAddr( of1 + (of2 << 16) ) )

    def setIpRange(self,index):
        '''
        设置二分查找法ip范围
        '''
        offset = self.firstIndex + index * 7
        self.ipdb.seek( offset )
        buf = self.ipdb.read( 7 )
        (self.curStartIp,of1,of2) = struct.unpack("IHB",buf)
        self.curEndIpOffset = of1 + (of2 << 16)
        self.ipdb.seek( self.curEndIpOffset )
        buf = self.ipdb.read( 4 )
        (self.curEndIp,) = struct.unpack("I",buf)

    def getIpAddr(self,ip):
        '''
        使用二分查找法搜索索引区，得到对应ip记录偏移地址
        '''
        L = 0
        R = self.indexCount - 1
        while L < R-1:
            M = (L + R) / 2
            self.setIpRange(M)
            if ip == self.curStartIp:
                L = M
                break
            if ip > self.curStartIp:
                L = M
            else:
                R = M
        self.setIpRange( L )
        if ip&0xffffff00L == 0xffffff00L:
            self.setIpRange( R )
        if self.curStartIp <= ip <= self.curEndIp:
            address = self.getAddr( self.curEndIpOffset )
            address = unicode(address,'gb2312').encode("utf-8")
        else:
            address = "未找到该IP的地址"
        return address

    def getIpRange(self,ip):
        '''
        得到该ip所属ip地址段
        '''
        self.getIpAddr(ip)
        range = self.ip2str(self.curStartIp) + ' - ' \
            + self.ip2str(self.curEndIp)
        return range

    def getString(self,offset = 0):
        if offset :
            self.ipdb.seek( offset )
        str = ""
        ch = self.ipdb.read( 1 )
        (byte,) = struct.unpack('B',ch)
        while byte != 0:
            str = str + ch
            ch = self.ipdb.read( 1 )
            (byte,) = struct.unpack('B',ch)
        return str

    def ip2str(self,ip):
        '''
        int型ip转换为str型ip，该ip为整数
        '''
        return str(ip>>24)+'.'+str((ip>>16)&0xffL)+'.' \
            +str((ip>>8)&0xffL)+'.'+str(ip&0xffL)

    def str2ip(self,s):
        '''
        将str型ip转换为little-endian型long
        '''
        (ip,) = struct.unpack('>L',socket.inet_aton(s))    #little-endian,网络字节顺序转换为little-endian
        return ip

    def getLong3(self,offset = 0):
        if offset :
            self.ipdb.seek( offset )
        str = self.ipdb.read(3)
        (a,b) = struct.unpack('HB',str)
        return (b << 16) + a


def main():
    conn = MysqlConnection().return_conn()
    cursor = conn.cursor()
    cursor.execute('select ip from ip_location')
    IPL = IPLocator( )
    
    for ip in cursor.fetchall():
        address = IPL.getIpAddr( IPL.str2ip(str(ip[0])) )   #str2ip使查询ip的格式与数据库中的相同
        print ip[0],address
        
    IPL.getIndexCount()      #输出版本信息和记录总数
    cursor.close()
    conn.close()

if __name__ == "__main__" :
    main()