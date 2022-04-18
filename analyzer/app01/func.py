# -*- coding: utf-8 -*-
# author: rogen

from cStringIO import StringIO
from analyzer import settings
from models import File_pcap, Bugs_content, sniff_Project, Bugs, Bugs_content, Repoters, Scan_result
from scapy.all import *
# from pymongo import MongoClient as Client

import collections
import os,sys,math
import pyshark
# import MySQLdb
import psutil
import urllib
import threading
import chardet
import re
import ConfigParser
import hashlib
import cgi


class Client(object):
    def __init__(self):
        self.cache = collections.OrderedDict()
    
    def __getattr__(self, item):
        self.cache.update({item: Client()})
        return self.cache[item]

    def insert_one(self, val):
        self.cache.setdefault('db', []).append(val)

    def count(self, filters):
        count = 0
        for d in self.cache.get('db', []):
            for k, v in filters.iteritems():
                if d.get(k, None) != v:
                    break
            else:
                count += 1
        return count

    def find(self, filters):
        items = []
        for d in self.cache['db']:
            for k, v in filters.iteritems():
                if isinstance(v, dict) and d.get(k, None) is not None:
                    for kc, vc in v.iteritems():
                        if "$gte" == kc:
                            if d[k] >= vc:
                                continue
                            else:
                                # 不满足条件
                                break
                        elif "$lte" == kc:
                            if d[k] <= vc:
                                continue
                            else:
                                break
                        else:
                            break
                    else:
                        # 含有匹配条件未命中条件
                        continue
                    # 全部命中，跳出后append
                    break
                elif d.get(k, None) != v:
                    break
            else:
                items.append(d)
        return items

    def remove(self, filters):
        items = []
        db = self.cache.get('db', [])
        for d in db:
            for k, v in filters.iteritems():
                if isinstance(v, dict) and d.get(k, None) is not None:
                    for kc, vc in v.iteritems():
                        if "$gte" == kc:
                            if d[k] >= vc:
                                continue
                            else:
                                # 不满足条件
                                break
                        elif "$lte" == kc:
                            if d[k] <= vc:
                                continue
                            else:
                                break
                        else:
                            break
                    else:
                        # 含有匹配条件未命中条件
                        continue
                    # 全部命中，跳出后append
                    break
                elif d.get(k, None) != v:
                    break
            else:
                items.append(d)
        self.cache['db'] = list(set(db) ^ set(items))
        return True


apppath = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = apppath + '/pcapfiles/'
BUGS_FOLDER = apppath + '/bugsfiles/'
PER_FILE_PKTS = 50
ALLOWED_EXTENSIONS = set(['pcap','pcapng','cap'])
conn = None
db = None
count = 0
client = Client()               #连接mongoclinet

bugs = client.bugs           #创建bugs数据库
list_bugs_info = bugs.bugs_info   #创建bugs_info聚集,相当于表
content_num = 0
mutex = threading.Lock()


#获取数据库连接
def get_connection():
    global conn,db
    if conn != None:
        try:
            conn.close()
        except:
            pass
    conn = MySQLdb.connect(settings.DATABASES['default']['HOST'],\
                    settings.DATABASES['default']['USER'],\
                    settings.DATABASES['default']['PASSWORD'],\
                    settings.DATABASES['default']['NAME'],\
                           charset = "utf8")
    if db != None:
        try:
            db.close()
        except:
            pass
    db = conn.cursor()
    return db


#获取数据条目
def show_entries():
    # db = get_connection()
    # db.execute('select * from app01_file_pcap')
    rows = File_pcap.objects.all()
    entries = [dict(id=row.id, filename=row.name, filepcap=row.pkt_counts, filesize=row.size,uploaddate=row.uploaddate) for row in rows]
    # entries = [dict({

    #         "filename": row.name,
            
    #     }) for row in rows]
    for i in entries:
        tmp = str(i["filename"])
        tmp = str(i["filename"])
        if "_" in tmp:
            pl = tmp.split("_")
            if len(pl) == 2:
                spid = pl[0]
                spfile = pl[1]
                flag = None
                try:
                    flag = True if sniff_Project.objects.filter(id=int(spid)) else False
                except:
                    i["file"] = i["filename"]
                else:
                    i["file"] = (sniff_Project.objects.get(id=int(spid)).pro_name + ":" if flag else  "已删除所属项目:") + spfile
        else:
            i["file"] = "外部导入文件：" + tmp

        entries[entries.index(i)] = i
    return entries


def show_pro_entries():
    # db = get_connection()
    # db.execute('select * from app01_sniff_project')
    rows = sniff_Project.objects.all()
    entries = [dict(id=row.id, pro_name=row.pro_name, filter=row.filter, pcap_name=row.pcap_name, netcard=row.netcard, \
                    pkt_counts=row.pkt_counts,pcap_size=row.pcap_size, stat=row.stat) for row in rows]
    return entries


def show_bug_entries():
    # db = get_connection()
    # db.execute('select * from app01_bugs')
    rows = Bugs.objects.all()
    entries = [dict(id=row.id, bugs_name=row.name,bugsdesc=row.desc) for row in rows]
    return entries


def show_reporter_entries(id):
    # db = get_connection()
    # db.execute('select * from app01_repoters where user_id=%d'%id)
    rows = Repoters.objects.filter(user_id=id)
    entries = [dict(id=row.id, name=row.repoter_name.split("_")[0]) for row in rows]
    return entries

def show_repodown_entries(id):
    # db = get_connection()
    # db.execute('select * from app01_repoters where id=%d'%id)
    # entries = [dict(id=row[0], name=row[2]) for row in db.fetchall()]
    # return entries

    rows = Repoters.objects.filter(id=id)
    entries = [dict(id=row.id, name=row.repoter_name) for row in rows]
    return entries

def show_reporterinfo_entries(id):

    # db = get_connection()
    # db.execute('select * from app01_repoters where id=%d'%id)
    # entries = [dict(reporter_summary=row[4]) for row in db.fetchall()]
    # return entries

    rows = Repoters.objects.filter(user_id=id)
    entries = [dict(reporter_summary=row.repoter_summary) for row in rows]
    return entries

def show_reporter(pname):

    # db = get_connection()
    # db.execute('''select * from app01_repoters where pcap_name="%s"''' % pname)
    # entries = [dict(id=row[0], reporter_name=row[2], reporter_summary=row[3], time=row[6], report_down=row[5]) for row in db.fetchall()]
    # return entries
    rows = Repoters.objects.filter(pcap_name=pname)
    entries = [dict(id=row.id,reporter_summary=row.repoter_summary,reporter_name=row.repoter_name,
        time=row.update_time,report_down=row.report_down) for row in rows]
    return entries


#获取包信息
def get_pcap_entries(id):
    # db = get_connection()
    # db.execute('''select * from app01_file_pcap where id="%d"''' % int(id))
    # entries = [dict(id=row[0], filename=row[1], filepcap=row[3], filesize=row[2], uploaddate=row[4]) for row in
    #            db.fetchall()]
    rows = File_pcap.objects.filter(id=int(id))
    entries = [dict(id=row.id, filename=row.name, filepcap=row.pkt_counts, filesize=row.size,uploaddate=row.uploaddate) for row in rows]
    # entries = [dict({
    for i in entries:
        tmp = str(i["filename"])
        if "_" in tmp:
            pl = tmp.split("_")
            if len(pl) == 2:
                spid = pl[0]
                spfile = pl[1]
                flag = None
                try:
                    flag = True if sniff_Project.objects.filter(id=int(spid)) else False
                except:
                    pass
                else:
                    i["file"] = (sniff_Project.objects.get(id=int(spid)).pro_name + ":" if flag else  "已删除所属项目:") + spfile
                entries[entries.index(i)] = i
        else:
            i["file"] = "外部导入文件：" + tmp
            entries[entries.index(i)] = i
    return entries


#执行sql命令
def sql_exec(sql):
    db = get_connection()
    db.execute(sql)
    # print "[*]execute sql: " + sql
    db.commit()


#列出文件，与数据库进行对比合并操作
def list_file():
    files = os.listdir(UPLOAD_FOLDER)

    if '.DS_Store' in files:
        files.remove('.DS_Store')
    dbfiles = [entry['filename'] for entry in show_entries()]
    for file in files: #循环处理pcap文件，不在库里的存库，库里残留的删掉
        file = file.decode("utf-8")
        if file in dbfiles:
            pass
        elif '.pcap' not in file:
            pass
        else:
            filesize = convertBytes(os.path.getsize(UPLOAD_FOLDER+file))
            pcapnum = get_capture_count(UPLOAD_FOLDER+file)
            mc = File_pcap.objects.all()
            mc.create(name=file, size=filesize,pkt_counts=str(pcapnum),uploaddate=time.strftime(r'%Y.%m.%d_%H:%M',time.localtime(time.time())))
    for dbfile in dbfiles:
        if dbfile.encode("utf8") not in files:
            md = File_pcap.objects.get(name=dbfile)
            md.delete()
        else:
            pass


#获取数据包数目
def get_capture_count(filename):
    p = pyshark.FileCapture(filename, only_summaries=True, keep_packets=False)
    p.load_packets()
    return len(p)


#文件大小表示
def convertBytes(bytes, lst=['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']):
    i = int(math.floor(math.log(bytes, 1024)))
    if i >= len(lst):
        i = len(lst) - 1
    return ('%.2f' + " " + lst[i]) % (bytes/math.pow(1024, i))


#判断文件后缀
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


#获取包内容
def decode_capture_file(pcapfile, num, filter=None):

    global count
    if filter:
        cap = pyshark.FileCapture(pcapfile, keep_packets=False, only_summaries=True, display_filter=filter)
    else:
        cap = pyshark.FileCapture(pcapfile, keep_packets=True, only_summaries=True)

    cap.load_packets()
    if len(cap) == 0:
        return 0, 'No packets found.'
    details = {
        'stats': {
            'breakdown': {},
            'length_buckets': {'0-200': 0, '201-450': 0, '451-800':0, '801-1200':0, '1201-1500': 0}
        },
        'packets': [],

    }
    avg_length = []
    #解包

    def decode_packet(packet):
        pkt_details = {
            'number' : int(packet.no) + num * PER_FILE_PKTS,
            'length' : packet.length,
            'time' : packet.time
        }
        pkt_details['src_ip'] = packet.source
        pkt_details['dst_ip'] = packet.destination
        pkt_details['protocol'] = packet.protocol
        pkt_details['desc'] = packet.info
        # delta and stream aren't supported by earlier versions (1.99.1) of tshark
        try:
            pkt_details['delta'] = packet.delta
            pkt_details['stream'] = packet.stream
        except AttributeError:
            pass

        details['packets'].append(pkt_details)
        avg_length.append(int(packet.length))

        if 0 <= int(packet.length) <= 200:
            details['stats']['length_buckets']['0-200'] += 1
        elif 201 <= int(packet.length) <= 450:
            details['stats']['length_buckets']['201-450'] += 1
        elif 451 <= int(packet.length) <= 800:
            details['stats']['length_buckets']['451-800'] += 1
        elif 801 <= int(packet.length) <= 1200:
            details['stats']['length_buckets']['801-1200'] += 1
        elif 1201 <= int(packet.length):
            details['stats']['length_buckets']['1201-1500'] += 1
        try:
            details['stats']['breakdown'][packet.protocol] += 1
        except KeyError:
            details['stats']['breakdown'][packet.protocol] = 1

    try:
        cap.apply_on_packets(decode_packet)
    except Exception,err:
        return (0,str(err))

    details['stats']['avg_length'] = sum(avg_length) / len(avg_length)
    return details


#获取包细节
def get_packet_detail(pcapfile, num):
    cap = pyshark.FileCapture(pcapfile)

    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()

    cap[int(num)-1].pretty_print()
    sys.stdout = old_stdout
    detail = '''
<script type="text/javascript">
$(document).ready(function(){
    $('.ui.accordion').accordion();
});
</script>
<i class="close icon"></i>
<div class="header">
    Packet Details
</div>
<div class="content">'''
    for line in mystdout.getvalue().split('\n'):
        if line == 'self._packet_string':
            continue
        elif 'Layer ETH' in line:
            detail += '''
    <div class="ui black segment" style="height:29rem;overflow:auto">
        <div class="ui styled fluid accordion">
            <div class="active title">
                <i class="dropdown icon"></i>
                <a class="packetHeader" data-target="#%(link)s">%(name)s</a>
            </div>
            <div id="%(link)s" class="active content">
                <div class="ui black segment">
            ''' % {'name': line[:-1], 'link': line.replace(' ', '-').strip(':')}
        elif 'Layer' in line:
            detail += '''
                </div>
            </div>
        </div>
        <div class="ui styled fluid accordion">
            <div class="title">
                <i class="dropdown icon"></i>
                <a class="packetHeader" data-target="#%(link)s">%(name)s</a>
            </div>
            <div id="%(link)s" class="content">
                <div class="ui black segment">
            ''' % {'name': line[:-1], 'link': line.replace(' ', '-').strip(':')}
        else:
            keyword = line.split(': ')[0] + ': '

            try:
                value = line.split(': ')[1]
            except IndexError:
                keyword = ''
                value = line

            try:
                keyword = keyword.split('= ')[1]
            except IndexError:
                pass

            detail += '<p><strong>%s</strong>%s</p>\n' % (keyword, value)
    detail += '''
                </div>
            </div>
        </div>
    </div>
'''
    return detail


#获取包信息
def get_statistics(file):
    tcp = 0
    udp = 0
    arp = 0
    icmp = 0
    other = 0
    pcapstat = {}
    # print 'rdpcaping...'
    pcap = rdpcap(file)
    # print 'rdpcap end!'
    for packet in pcap:
        if 'TCP' in packet:
            tcp = tcp + 1
        elif 'UDP' in packet:
            udp = udp + 1
        elif 'ARP' in packet:
            arp = arp + 1
        elif 'ICMP' in packet:
            icmp = icmp + 1
        else:
            other = other + 1
    pcapstat['tcp'] = str(tcp)
    pcapstat['udp'] = str(udp)
    pcapstat['arp'] = str(arp)
    pcapstat['icmp'] = str(icmp)
    pcapstat['other'] = str(icmp)
    pcapstat['total'] = str(tcp + udp + arp + icmp + other)
    return pcapstat


#获取包来源地址
def get_ip_src(file):
    ipsrc = []
    pcap = rdpcap(file)
    for packet in pcap:
        if 'TCP' in packet:
            ipsrc.append(packet.getlayer('IP').src)
    ipsrclist = collections.Counter(ipsrc)
    ipsrclist=ipsrclist.most_common()
    return ipsrclist


#获取包去向地址
def get_ip_dst(file):
    ipdst = []
    pcap = rdpcap(file)
    for packet in pcap:
        if 'TCP' in packet:
            ipdst.append(packet.getlayer('IP').dst)
    ipdstlist = collections.Counter(ipdst).most_common()
    return ipdstlist


#获取包去向端口
def get_port_dst(file):
    dstport = []
    pcap = rdpcap(file)
    for packet in pcap:
        if 'TCP' in packet:
            dstport.append(packet.getlayer('TCP').dport)
    dstportlist = collections.Counter(dstport).most_common()
    return dstportlist


#获取DNS请求
def get_dns(file):
    dns = []
    pcap = rdpcap(file)
    for packet in pcap:
        if 'DNS' in packet:
                res = packet.getlayer('DNS').qd.qname
                if res[len(res) - 1] == '.':
                    res = res[:-1]
                dns.append(res)

    a=['a','b','c']
    dns = collections.Counter(dns)

    dns=dns.most_common()
    dnstable ='''
<table class="ui table">
    <thead>
        <tr>
        <th class="twelve wide">DNS Request</th>
        <th class="four wide">Request Num</th>
        </tr>
    </thead>
    <tbody>
'''
    for dnsreq in dns:
        dnstable += '''
        <tr>
            <td>
            %(dns)s
            </td>
            <td>
            %(num)s
            </td>
        </tr>
''' % { 'dns':dnsreq[0],'num':str(dnsreq[1])}
    dnstable += '''
    </tbody>
  </table>
'''
    return dns,dnstable


#邮件数据包提取
def get_mail(file):
    mailpkts = []
    result = "<p>"
    pcap = rdpcap(file)
    for packet in pcap:
        if 'TCP' in packet:
            if packet.getlayer('TCP').dport == 110 or packet.getlayer('TCP').sport == 110 or packet.getlayer('TCP').dport == 143 or packet.getlayer('TCP').sport == 143 :
                mailpkts.append(packet)
    for packet in mailpkts:
        if packet.getlayer('TCP').flags == 24:
            result = result + packet.getlayer('Raw').load.replace(' ','&nbsp;').replace('\n','<br/>')
    if result == "<p>":
        result = result + "No Mail Packets!"
    result = result + "</p>"
    result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\\x80-\\xff]').sub('', result)
    return result


#Web数据包提取，过滤
def get_web(file,num):
    webpkts={}
    result_list=[]
    index = int(num)
    count = 0
    pcap = rdpcap(file)
    #html = [">","<","<div","/div>","<?php>","<php>","<a>","</a>","<style>","</style>","<html>","</html>","<body>","</body>","<scripy>","</script>","<div>","</div>","</p>"]
    for packet in pcap:
        count += 1
        if 'TCP' in packet:
            webpkts[str(count)] = packet
    for packet in webpkts.values():
        result = ""
        flag = 1
        if packet.getlayer('TCP').flags == 24:
            for k in webpkts.keys():
                if webpkts[k] == packet:
                    num = k
            count = index * PER_FILE_PKTS + int(num)
            raw = packet.getlayer('Raw').load.replace("&", "&amp;").replace('''"''', "&quot;").replace(">","&gt;").replace("<","&lt;").replace("'","&#39;")
            result = result + '''<div class="ui vertical segment"><span>%s</span><br/><p>''' % str(count)
            # for h in html:
            #     if h in raw:
            #         flag = 0
            #         raw = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\\x80-\\xff]').sub('', raw)
            #         result_list.append({"flag":flag,"result":raw,"count":count})
            #         break
            if flag:
                raw = raw.replace(' ', '&nbsp;').replace('\n', '<br>')
                result += raw
                result = result + '''</p></div>'''
                result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\\x80-\\xff]').sub('', result)
                result_list.append({"flag": flag, "result": result})
        else:
            pass
    return result_list


#扫描处理
def filter_packet(file, num, idstr, timelayer, bugs_info, mutex):
    '''
    处理内部变量时，一定要分清作用域，函数的，模块的，传递的
    :param file:
    :param num:
    :return:ret = [
        {"packet_num":1,"packet_content":"result","bugs_filter":"and 1=1","bugs_name":"sql_inj","protocol":"http"},
        {},
        ...
    ]
    '''
    global content_num
    webpkts = {}
    index = int(num)
    pcap = sniff(offline=file,timeout=2)
    count = 0
    bugs_feature = get_filter(idstr)
    for packet in pcap:
        count += 1
        if 'TCP' in packet:
            webpkts[str(count)] = packet             #将包对象，以字典形式保存

    for packet in webpkts.values():                 #循环处理100个包，对每一个包内容都做一遍扫描，最后生成结果，返回(节省空间)
        result = ""                                 #清空
        bugs_name_str = ""
        escape_flag = 1
        if packet.getlayer('TCP').flags == 24:     #判断是否含有Raw层
            for k in webpkts.keys():
                if webpkts[k] == packet:
                    num = k                         #num标记包在子包文件中的次序
            count = index * PER_FILE_PKTS + int(num)#计算出此包在整个包文件中的次序

            #为原始数据包装上HTML元素
            raw = packet.getlayer('Raw').load.replace("&", "&amp;").replace('''"''', "&quot;").replace(">","&gt;").replace("<","&lt;").replace("'","&#39;")
            raw_tmp = raw.replace(' ', '&nbsp;').replace('\n', '<br>')
            # for h in html:
            #     if h in raw:  # raw里含有html标签
            #         escape_flag = 0  # 需要on
            #         break
            encoding = chardet.detect(raw)['encoding']#保存Raw层字符的编码格式
            if encoding is 'ascii':
                flag = False
                tmp_content_num = 0
                for bugs_name in bugs_feature.keys():  # 循环处理每一个漏洞规则字符串
                    for bugs in bugs_feature[bugs_name]:
                        try:
                            match_list = re.findall(bugs, raw_tmp, re.IGNORECASE)    #正则匹配查找，忽略大小写
                            if len(match_list) != 0:                                #如果匹配到字符
                                flag = True
                                if bugs_name not in bugs_name_str:
                                    bugs_name_str += bugs_name + "<br>"
                                if escape_flag:
                                    result_bugs = raw_tmp
                                    for m in match_list:                                #循环处理匹配到的字符串:高亮
                                        turn = match_list.count(m)
                                        reds = '''<span style="color:red;font-weight:bold;">%s</span>''' % m
                                        result_bugs = re.sub(m, reds, result_bugs, turn)
                                        if turn > 1:
                                            for m1 in match_list:
                                                for m2 in match_list[match_list.index(m1)+1:]:
                                                    if m2 == m1:
                                                        match_list.remove(m2)
                                    raw_tmp = result_bugs
                            else:
                                continue
                        except Exception, err:
                            print "filter_packet error:", str(err)
                            pass
                #扫描完毕一个包后，入库
                if flag:                                    #此包有漏洞，进入
                    if mutex.acquire():
                        content_num += 1                    #找到一个有漏洞的包，计数器加1，做分页用
                        tmp_content_num = content_num
                        mutex.release()
                    packet_dict = {}
                    packet_dict["packet_num"] = count
                    packet_dict["content_num"] = tmp_content_num        #由于线程竞争存在可能排序会有错乱，但是不影响分页展示
                    key = os.path.dirname(file).split("/")[-2]
                    match = key + str(timelayer) + str(bugs_feature)
                    match_hash = hashlib.md5(match).hexdigest()
                    packet_dict["keystone"] = match_hash
                    packet_dict["bugs_name"] = bugs_name_str

                    if not escape_flag:
                        packet_dict["escape"] = 0 #autoescape on
                        packet_dict["content"] = raw
                    else:
                        packet_dict["escape"] = 1
                        raw_tmp2 = raw_tmp.split("<br>")
                        raw_str = ""
                        str_flag = '''<span style="color:red;font-weight:bold;">'''
                        for i in raw_tmp2:
                            raw_str += '''<span style="border-bottom:1px solid red;">%s</span><br>''' % i if str_flag in i else i + "<br>"
                        result = result + '''<div class="ui vertical segment"><p width="50%" style="word-wrap:break-word;word-break:break-all">'''
                        result = result + raw_str
                        result = result + '''</p></div>'''
                        packet_dict["content"] = result
                    bugs_info.insert_one(packet_dict)


#获取本地网卡信息
def get_netcard():
	netcard_info = []
	info = psutil.net_if_addrs()
	for k,v in info.items():
		for item in v:
			if item[0] == 2:
				netcard_info.append((k,item[1]))
	return netcard_info


#处理漏洞规则,url编码化
def get_filter(idselect):
    '''
    用前台筛选过来的id('1,2,3,4')找到库中对应的filter_string.
    :param idselect:字符串
    :return:ret = {
        "对应的规则名称"：[选中的规则字符串列表]，
        ...
    }
    '''
    ret = {}
    try:
        for i in idselect.split(','):           #循环处理id
            if i == "":
                continue
            id = int(i)
            bc = Bugs_content.objects.get(id=id)
            key = bc.name.name                  #获取bugs_content的外键Bugs的name
            if key not in ret.keys():
                ret[key] = []
            fs = bc.filter_string
            if key == "SQL_Injection":
                fs = fs.split("[")[0] if "[" in fs else fs
                fs = fs if "%" in fs else urllib.quote(fs)
            elif key == "XSS":
                fs = cgi.escape(fs)
            else:
                fs = fs.split("[")[0] if "[" in fs else fs
                fs = fs if "%" in fs else urllib.quote(fs)
                fs = cgi.escape(fs)
            ret[key].append(fs)

    except Exception,err:
        print "get_filter error",str(err)

    return ret


#获取网卡信息=
def getNetwork():
    netlist = get_netcard()
    netstrlist = []
    for net in netlist:
        str = net[0] + '  :  ' + net[1]
        netstrlist.append(str)
    ret = {
        'Iface':netstrlist,
    }
    return netstrlist
    pass


#获取子包文件名
def getChildrenfile(id=-1, num=-1, filepath=''):
    '''

    :param id:
    :param num:
    :param filepath: 不存在路径时，直接给出文件名
    :return:
    '''
    if id != -1:                                #查库获取子包文件夹名字,给出id不用给filepath
        id = int(id)
        pcapfile_entries = get_pcap_entries(id)
        bigfile = pcapfile_entries[0]['filename']
        bigfilepath = bigfile[0:-5]
        if num != -1:                           #返回在库里存有pcap文件名，在filepath路径下的第num个子包文件全名称
            filename = ''
            num = str(num)
            pcapfilelist = os.listdir(UPLOAD_FOLDER + bigfilepath + "/")
            beforenum = '_' + (5 - len(num)) * '0' + num + '_'

            for f in pcapfilelist:
                if beforenum in f:
                    filename = f
                    break
                else:
                    continue
            return UPLOAD_FOLDER + bigfilepath + "/" + filename
        else:                                   #没有指定num，返回子包文件夹名字
            return bigfilepath
    elif id == -1 and num != -1:                              #给定num获取子包文件夹下的pcap文件全名称，此pcap文件未在库中
        filename = ''
        num = str(num)
        pcapfilelist = os.listdir(filepath)
        beforenum = '_' + (5 - len(num)) * '0' + num + '_'
        for f in pcapfilelist:
            if beforenum in f:
                filename = f
                break
            else:
                continue
        return filepath + "/"+ filename
    else:
        pass


#线程类
class Pcapthread(threading.Thread):
    '''
    每一个线程处理100个子包文件，
    '''
    def __init__(self, db, name, filepath, tailnum, start, stop, bugsid, flag=False):
        '''

        :param name:        线程名字标示，用以创建漏洞报告文件
        :param filepath:    子包文件路径
        :param tailnum:     每个线程需要处理的100个文件中的最后一个文件序号
        :param flag:        是否有100个文件的标志位
        '''
        super(Pcapthread,self).__init__()
        self.setName(name)
        self.num = tailnum

        self.filepath = filepath
        self.flag=flag
        self.pcapfilename = self.filepath.split("/")[-1] + ".pcap"
        self.bugs_info = list_bugs_info
        self.bugs_id = bugsid
        self.start_time = start
        self.stop_time = stop

    def run(self):
        global mutex
        time_layer = {
            "start_time": self.start_time,
            "stop_time": self.stop_time,
        }
        first = (self.num - 1) // PER_FILE_PKTS * PER_FILE_PKTS
        last = self.num
        for i in range(first, last):  # 循环处理每一个子包文件
            pcapfilename = getChildrenfile(-1, i, self.filepath)  # 获取子包文件名
            filter_packet(pcapfilename, i, self.bugs_id, time_layer, self.bugs_info, mutex)  # 处理一个子包文件，返回扫描结果


#动态生成线程实例
def filter_Bugs(bugsfile, start_time, stop_time, bugsid):
    '''
    生成漏洞文件存放目录，按照子包文件个数出生成对应数量的线程.
    :param bugsfile:        扫描文件存放路径
    :param start_time:      扫描文件的开始时间字符串,2016-11-7_10:20:30
    :param stop_time:       扫描文件的结束时间
    :param bugsid:          扫描文件的漏洞规则id
    :return:
    '''
    global bugs, content_num
    timefilepath = ""
    content_num = 0 #清空全局计数器
    try:
        if not os.path.exists(BUGS_FOLDER):
            os.popen("mkdir %s" % BUGS_FOLDER)

        bugsname = BUGS_FOLDER + bugsfile
        if not os.path.exists(bugsname):
            os.popen("mkdir %s" % bugsname)  #创建与包名对应的scanbugs文件夹
        filepath = UPLOAD_FOLDER + bugsfile    #原始pcap包存放路径
        #根据起止时间，确定是否拆包，按功能需求添加

        timefilename = start_time + '__' + stop_time
        timefilepath = bugsname + "/" + timefilename        #每次扫描时生成的文件夹，用来存放按时间拆分后的包文件的子包文件
        if not os.path.exists(timefilepath) and not os.path.exists(timefilepath + ".pcap"):
            os.popen("mkdir %s" % timefilepath)
        #按起止时间拆分
        if stop_time != "false":
            os.popen("editcap -F libpcap -A %s -B %s %s %s" % (\
                        "'" + start_time.replace("time"," ") + "'", \
                        "'" + stop_time.replace("time"," ") + "'",\
                        filepath + ".pcap", timefilepath + ".pcap"
            ))
        else:
            os.popen("editcap -F libpcap -A %s  %s %s" % ( \
                "'" + start_time.replace("time", " ") + "'", \
                filepath + ".pcap", timefilepath + ".pcap"
            ))

        # print p
        #按包个数拆分
        os.popen("editcap -F libpcap -c %d %s %s" % (
                PER_FILE_PKTS, timefilepath +".pcap", timefilepath +"/bugs"
        ))

    except Exception,err:
        print "filter_Bugs error:",str(err)

    pcapname = os.listdir(timefilepath)
    thread_num = (len(pcapname)) // PER_FILE_PKTS
    tail = (len(pcapname) ) % PER_FILE_PKTS
    if tail:
        thread_num += 1
    else:
        tail = thread_num * PER_FILE_PKTS
    thread_list = []
    for i in range(0,thread_num):
        if i != thread_num - 1: #不是最后一组时
            tailnum = (i + 1) * PER_FILE_PKTS
            thread_list.append(Pcapthread(bugs, 'easyanalyzer_' + str(i), timefilepath, tailnum, start_time, stop_time, bugsid))
        else: #最后一组
            tailnum = tail + i * PER_FILE_PKTS

            thread_list.append(Pcapthread(bugs, 'easyanalyzer_' + str(i), timefilepath, tailnum, start_time, stop_time, bugsid, flag=True))
    for ts in thread_list:
        ts.start()
    for tj in thread_list:
        tj.join()
    content_num = 0         #所有线程走完后，计数器清零


#获取带扫描文件信息
def getScanfileinfo(id):
    ret = {
        "pcap_name": '',
        "pkts": "",
        "start_time": "",
        "stop_time": "",
        "pkts_per_second": '',
    }
    try:
        id = int(id)
        firstpcap = getChildrenfile(id, 0, UPLOAD_FOLDER)
        #print "firstpcap:",firstpcap
        pcappath = os.path.dirname(firstpcap)
        lastnum = len(os.listdir(pcappath)) - 1
        #print "lastnum:",lastnum
        lastpcap = getChildrenfile(id, lastnum, UPLOAD_FOLDER)
        #print "lastpcap:", lastpcap
        firstp = sniff(offline=firstpcap, count=1)[0]
	#print "firstp over"
        lastp = sniff(offline=lastpcap,timeout=1)
	#print "lastp over"
        start_time = time.strftime(r'%Y-%m-%d %H:%M:%S',time.localtime(firstp.time))
        stop_time = time.strftime(r'%Y-%m-%d %H:%M:%S',time.localtime(lastp[-1].time))
        pcap_name = pcappath.split('/')[-1] + '.pcap'
        if "_" in pcap_name:
            pl = pcap_name.split("_")
            if len(pl) == 2:
                spid = pl[0]
                spfile = pl[1]
                flag = None
                try:
                    flag = True if sniff_Project.objects.filter(id = int(spid)) else False
                except:
                    pass
                else:
                    pcap_name = (sniff_Project.objects.get(id=int(spid)).pro_name + ":" if flag else  "已删除所属项目:") + spfile
        else:
            pcap_name = "外部导入文件：" + pcap_name
        pkt_count = len(lastp) + lastnum * PER_FILE_PKTS
        per = pkt_count / (lastp[-1].time - firstp.time)
        size = os.path.getsize(os.path.dirname(firstpcap) + ".pcap")
        size = convertBytes(size)
        ret["pcap_name"] = pcap_name
        ret["pkts"] = pkt_count
        ret["size"] = size
        ret["start_time"] = str(start_time)
        ret["stop_time"] = str(stop_time)
        ret["pkts_per_second"] = int(per)
    except Exception,err:
        print "getScanfileinfo error:",str(err)
    return ret


#读取配置信息
def getConfig(filepath):
    bpf_filter = []
    report = []
    config_ = ConfigParser.RawConfigParser()
    config_.read(filepath)
    if config_.has_section('example_bpf'):
        for i in config_.items('example_bpf'):
            filter = {}
            filter["info"] = i[0]
            filter["example"] = i[1]
            bpf_filter.append(filter)

    if config_.has_section('report'):
        # print "report"
        for r in config_.items('report'):
            report_tmp = {}
            report_tmp["report_down"] = r[1]
            report.append(report_tmp)
            # print report_tmp

    ret = {
        "bpf_filter":bpf_filter,
        "repoter":report,
    }
    # print ret
    return ret


#拆包
def divdePcap(id):

    id = int(id)
    if File_pcap.objects.filter(id=id):
        path = UPLOAD_FOLDER + getChildrenfile(id)
        pcapname = path + ".pcap"
        if os.path.exists(pcapname):
            cmd = "editcap -F libpcap -C 100 %s %s" % (pcapname, path + "/")
            if os.path.exists(path + "/"):
                if os.listdir(path + "/") == 0:
                    os.popen(cmd)
            else:
                os.popen("mkdir -p %s" % path)
                os.popen(cmd)
            return 0
    else:
        return 1





