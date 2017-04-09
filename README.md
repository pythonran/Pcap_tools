# rybsup
网络流量可配置嗅探，流量包解析，漏洞规则扫描，生成报告. ....搞网络安全这块，还凑合着用吧.<br>
环境安装:<br>
python2.7 django>1.9 mysql mongo<br>
beautifulsoup4 (4.5.3)<br>
bs4 (0.0.1)<br>
certifi (2017.1.23)<br>
chardet (2.3.0)<br>
configparser (3.5.0)<br>
djangorestframework (3.6.2)<br>
futures (3.0.5)<br>
Logbook (1.0.0)<br>
lxml (3.7.3)<br>
MySQL-python (1.2.5)<br>
psutil (5.2.1)<br>
pymongo (3.4.0)<br>
pyshark (0.3.7.2)<br>
pytz (2017.2)<br>
scapy (2.3.3)<br>
setuptools (1.4.2)<br>
simplejson (3.10.0)<br>
singledispatch (3.4.0.3)<br>
six (1.10.0)<br>
tornado (4.4.3)<br>
trollius (1.0.4)<br>
Werkzeug (0.12.1)<br>
配置文件:<br>
[example_bpf]#BPF规则示范<br>
监听物理地址  = ether host 00:00:5e:00:53:00<br>
监听ARP = ether proto 0x0806<br>
滤出广播和多播 =  not broadcast and not multicast<br>
滤出ARP =  not arp<br>
只要IP4 =  ip<br>
IPv4地址 = host 192.0.2.1<br>
只要IPv6 = ip6<br>
IPv6地址  = host 2001:db8::1<br>
只要TCP = tcp<br>
只要UDP = udp<br>
80端口 = port 80<br>
TCP80端口 = tcp port 80<br>
滤出ARP、DNS = not arp and port not 53<br>
谷歌的非HTTP、SMTP包 = not port 80 and not port 25 and host www.google.org<br>
[report]#文件下载url，按照自己的IP改<br>
downloadurl = http://192.168.137.100:8000/<br>
如果提示找不到tshark，运行yum install wireshark<br>
1、配置嗅探项目<br>
 ![](https://github.com/pythonran/rybsup/blob/master/sniffer.jpg)
2、流量包管理<br>
 ![](https://github.com/pythonran/rybsup/blob/master/upload.png)
3、包详情查看<br>
 ![](https://github.com/pythonran/rybsup/blob/master/detail.png)
4、漏洞规则录入<br>
 ![](https://github.com/pythonran/rybsup/blob/master/bugs.png)
5、扫描配置<br>
 ![](https://github.com/pythonran/rybsup/blob/master/scanprofile.png)
6、扫描结果<br>
 ![](https://github.com/pythonran/rybsup/blob/master/scandetail.png)
7、选择性生成报告<br>
 ![](https://github.com/pythonran/rybsup/blob/master/repoter.png)
8、报告下载<br>
 ![](https://github.com/pythonran/rybsup/blob/master/repoters.png)
9、报告模板<br>
 ![](https://github.com/pythonran/rybsup/blob/master/final.png)
