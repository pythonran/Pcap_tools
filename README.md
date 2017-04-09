# rybsup
网络流量可配置嗅探，流量包解析，漏洞规则扫描，生成报告. ....搞网络安全这块，还凑合着用吧
环境安装：
python2.7 django>1.9 mysql mongo
beautifulsoup4 (4.5.3)
bs4 (0.0.1)
certifi (2017.1.23)
chardet (2.3.0)
configparser (3.5.0)
djangorestframework (3.6.2)
futures (3.0.5)
Logbook (1.0.0)
lxml (3.7.3)
MySQL-python (1.2.5)
psutil (5.2.1)
pymongo (3.4.0)
pyshark (0.3.7.2)
pytz (2017.2)
scapy (2.3.3)
setuptools (1.4.2)
simplejson (3.10.0)
singledispatch (3.4.0.3)
six (1.10.0)
tornado (4.4.3)
trollius (1.0.4)
Werkzeug (0.12.1)
配置文件:
[example_bpf]#BPF规则示范
监听物理地址  = ether host 00:00:5e:00:53:00
监听ARP = ether proto 0x0806
滤出广播和多播 =  not broadcast and not multicast
滤出ARP =  not arp
只要IP4 =  ip
IPv4地址 = host 192.0.2.1
只要IPv6 = ip6
IPv6地址  = host 2001:db8::1
只要TCP = tcp
只要UDP = udp
80端口 = port 80
TCP80端口 = tcp port 80
滤出ARP、DNS = not arp and port not 53
谷歌的非HTTP、SMTP包 = not port 80 and not port 25 and host www.google.org
[report]#文件下载url，按照自己的IP改
downloadurl = http://192.168.137.100:8000/
如果提示找不到tshark，运行yum install wireshark
1、配置嗅探项目
 ![image](https://github.com/pythonran/rybsup/blob/master/sniffer.jpg)
2、流量包管理
 ![image](https://github.com/pythonran/rybsup/blob/master/upload.jpg)
3、包详情查看
 ![image](https://github.com/pythonran/rybsup/blob/master/detail.jpg)
4、漏洞规则录入
 ![image](https://github.com/pythonran/rybsup/blob/master/bugs.jpg)
5、扫描配置
 ![image](https://github.com/pythonran/rybsup/blob/master/scanprofile.jpg)
6、扫描结果
 ![image](https://github.com/pythonran/rybsup/blob/master/scandetail.jpg)
7、选择性生成报告
 ![image](https://github.com/pythonran/rybsup/blob/master/repoter.jpg)
8、报告下载
 ![image](https://github.com/pythonran/rybsup/blob/master/repoters.jpg)
9、报告模板
 ![image](https://github.com/pythonran/rybsup/blob/master/final.jpg)
