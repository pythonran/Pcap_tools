# Pcap_tools
网络流量可配置嗅探，流量包解析，漏洞规则扫描，生成报告. ....搞网络安全这块，还凑合着用吧.<br>
<B>1、环境安装:</B><br>
    &nbsp;&nbsp;&nbsp;python2.7 django>1.9 mysql mongo<br>
    &nbsp;&nbsp;&nbsp;beautifulsoup4 (4.5.3)<br>
     &nbsp;&nbsp;&nbsp; bs4 (0.0.1)<br>
      &nbsp;&nbsp;&nbsp;certifi (2017.1.23)<br>
     &nbsp;&nbsp;&nbsp; chardet (2.3.0)<br>
    &nbsp;&nbsp;&nbsp;  configparser (3.5.0)<br>
     &nbsp;&nbsp;&nbsp; djangorestframework (3.6.2)<br>
     &nbsp;&nbsp;&nbsp; futures (3.0.5)<br>
    &nbsp;&nbsp;&nbsp; Logbook (1.0.0)<br>
     &nbsp;&nbsp;&nbsp; lxml (3.7.3)<br>
     &nbsp;&nbsp;&nbsp; MySQL-python (1.2.5)<br>
    &nbsp;&nbsp;&nbsp;  psutil (5.2.1)<br>
    &nbsp;&nbsp;&nbsp;  pymongo (3.4.0)<br>
     &nbsp;&nbsp;&nbsp; pyshark (0.3.7.2)<br>
     &nbsp;&nbsp;&nbsp; pytz (2017.2)<br>
     &nbsp;&nbsp;&nbsp; scapy (2.3.3)<br>
     &nbsp;&nbsp;&nbsp; setuptools (1.4.2)<br>
     &nbsp;&nbsp;&nbsp; simplejson (3.10.0)<br>
     &nbsp;&nbsp;&nbsp; singledispatch (3.4.0.3)<br>
     &nbsp;&nbsp;&nbsp; six (1.10.0)<br>
     &nbsp;&nbsp;&nbsp; tornado (4.4.3)<br>
     &nbsp;&nbsp;&nbsp; trollius (1.0.4)<br>
    &nbsp;&nbsp;&nbsp;  Werkzeug (0.12.1)<br>
    <br>
    配置好settings中的DATABASES；<br>
    新建数据库；<br>
    运行python manage.py check无报错；<br>
    运行python manage.py makemigrate && python manage.py migrate 建立表结构<br>
<B>2、配置文件:</B>app01_config<br>
    &nbsp;&nbsp;&nbsp;[example_bpf]#BPF规则示范<br>
    &nbsp;&nbsp;&nbsp;监听物理地址  = ether host 00:00:5e:00:53:00<br>
    &nbsp;&nbsp;&nbsp;监听ARP = ether proto 0x0806<br>
    &nbsp;&nbsp;&nbsp;滤出广播和多播 =  not broadcast and not multicast<br>
    &nbsp;&nbsp;&nbsp;滤出ARP =  not arp<br>
    &nbsp;&nbsp;&nbsp;只要IP4 =  ip<br>
    &nbsp;&nbsp;&nbsp;IPv4地址 = host 192.0.2.1<br>
    &nbsp;&nbsp;&nbsp;只要IPv6 = ip6<br>
    &nbsp;&nbsp;&nbsp;IPv6地址  = host 2001:db8::1<br>
    &nbsp;&nbsp;&nbsp;只要TCP = tcp<br>
    &nbsp;&nbsp;&nbsp;只要UDP = udp<br>
    &nbsp;&nbsp;&nbsp;80端口 = port 80<br>
    &nbsp;&nbsp;&nbsp;TCP80端口 = tcp port 80<br>
    &nbsp;&nbsp;&nbsp;滤出ARP、DNS = not arp and port not 53<br>
    &nbsp;&nbsp;&nbsp;谷歌的非HTTP、SMTP包 = not port 80 and not port 25 and host www.google.org<br>
    &nbsp;&nbsp;&nbsp;[report]#文件下载url，按照自己的IP改<br>
    &nbsp;&nbsp;&nbsp;downloadurl = http://192.168.137.100:8000/<br>
<B>如果提示找不到tshark，运行yum install wireshark</B><br>
<br>
<B>3、配置嗅探项目</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/sniffer.jpg)
<B>4、流量包管理</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/upload.png)
<B>5、包详情查看</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/detail.png)
<B>6、漏洞规则录入</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/bugs.png)
<B>7、扫描配置</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/scanprofile.png)
<B>8、扫描结果</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/scandetail.png)
<B>9、选择性生成报告</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/repoter.png)
<B>10、报告下载</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/repoters.png)
<B>11、报告模板</B><br>
 ![](https://github.com/pythonran/rybsup/blob/master/final.png)
