#!C:\Python27/python
#encoding:utf-8
"""
实现根据城市转换为经纬度的功能
只是简单的实现功能，最后集成到分布式中
"""
import urllib2
import json
import MySQLdb
import sys
reload(sys)
sys.setdefaultencoding('utf8')


conn=MySQLdb.Connection(host='172.26.253.3',user='root',passwd='platform',db='platform_schema_gd',charset='utf8')
cursor = conn.cursor()

cursor.execute("SELECT city FROM ip_province_result where longitude = '' or longitude is NULL ")
ip_citys = cursor.fetchall()             #得到要查询的ip所在城市
ip_citys_qu = list(set(ip_citys))        #去重

cursor.execute('SELECT  city_name,longitude,latitude FROM dns_city_coordinate') 
cor_citys = cursor.fetchall()            #获得城市经纬度

sql = "update ip_province_result set longitude = %s,latitude = %s where city = %s"

for ip_city in ip_citys_qu:
    for cor_city in cor_citys:
        if cor_city[0] in ip_city[0]:
            longitude = cor_city[1]
            latitude = cor_city[2]
            break
        else:
            longitude = ''
            latitude = ''
    cursor.execute(sql,(longitude,latitude,ip_city[0]))
    conn.commit()

cursor.close()
conn.close()
print 'done'