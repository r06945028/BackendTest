import dpkt
import datetime
import socket
import pymysql

f = open('./tcpdump/20190821-1311.pcap','rb')
pcap = dpkt.pcap.Reader(f)
count=0
data_list=[]

conn = pymysql.connect(host='localhost', port=3306, user='root', passwd='test', db= 'pcap_file')
cursor = conn.cursor()

for ts, buf in pcap:
    data=[]
#     print ('Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts)))
    date_str = datetime.datetime.utcfromtimestamp(ts).strftime("%Y/%m/%d") 
    time_str = datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M:%S")
    usec=int(1000000*(ts-int(ts)))
   
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    src=str(ip.src)
    dst=str(ip.dst)
    # print(ip.src[0])
    # print(count)
    # if ip.src[0]!='$' and ip.src[0]!=' ' and ip.src[0]!='*' and ip.src[0]!='&':
    #     src = socket.inet_ntoa(ip.src)
    #     dst = socket.inet_ntoa(ip.dst)
    data.append(date_str)
    data.append(time_str)
    data.append(str(usec))
    data.append(src)
    data.append(str(ip.data.sport))
    data.append(dst)
    data.append(str(ip.data.dport))
    data.append("")
    # print(data)
    # data_list.append(data)
    effect_row = cursor.execute("INSERT into files (date, time, usec, SourceIP, SourcePort, DestinationIP, DestinationPort, FQDN) values (%s, %s, %s, %s, %s, %s, %s, '')",(data[0],data[1],data[2],data[3],data[4],data[5],data[6]))
    count+=1
    # if count>100:
    #     break



# effect_row = cursor.execute("CREATE TABLE files (date VARCHAR(25), time VARCHAR(25), usec INT(20), SourceIP VARCHAR(128), SourcePort INT(20), DestinationIP VARCHAR(128), DestinationPort INT(20), FQDN VARCHAR(128))")
# print(effect_row)
# count=0
# for d in data_list:
    
    # print(effect_row)
    # count+=1
    # if count>90:
    #     break
    
conn.commit()
cursor.close()
conn.close()
print(data_list)
f.close() 