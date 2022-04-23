# Pcap_tools
version: python2
cd analyzer
pip2 install -r require.txt
python2 manage.py check
python2 manage.py migrate
python2 manage.py runserver 0.0.0.0:9000
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
