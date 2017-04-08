# -*- coding: utf-8 -*-
from scapy.all import *
import signal

#抓包类
class single_sniff():

    def __init__(self,pidname,netcard, pcapname,dstfile,sfilter, count=-1, filesize=-1):
        try:
            self.sfilter = sfilter
            self.netcard = netcard
            self.pidfile = pidname
            self.pkt_count = 0
            self.filepath = os.path.dirname(os.path.abspath(__file__)) + '/sniffpcap/'
            if not os.path.exists(self.filepath):
                os.mkdir(self.filepath)
            self.filename = self.filepath + pcapname #嗅探完毕，保存下来的文件
            self.pcapname = pcapname
            self.count = count
            self.filemaxsize = filesize
            self.curfilesize = 0
            self.dstfile = dstfile  #最终包文件路径
            fp = file(self.pidfile, 'w+')
            fp.write('%s \n' % os.getpid())
            fp.close()
        except Exception,err:
            fp = open("/analyzer/log.txt", "a+")
            fp.write(time.strftime(r'%Y.%m.%d_%H:%M', time.localtime(time.time())) + "<single_sniff.__init__> " + str(err) + "\n")
            fp.close()

    def run(self):
        signal.signal(signal.SIGUSR1, self.stop)
        try:
            if self.sfilter:
                sniff( iface=self.netcard, filter=self.sfilter, prn=self.wto_pcap, count= int(self.count))
                dst_dirname = self.dstfile + self.pcapname[0:-5] #生成对应包的子包文件夹名字
                if not os.path.exists(dst_dirname):
                    os.system("mkdir %s" % dst_dirname)#创建子包文件夹
                os.system("editcap -c 100 -F libpcap %s %s" % (self.filename,dst_dirname + '/easyedu'))#进行拆分，将嗅探包文件，拆分到pcap包文件路径下，并加上easyedu前缀
                os.system("mv %s %s" % (self.filename, self.dstfile)) #将嗅探文件，移到pcap包文件目录下
                if os.path.exists(self.pidfile):
                    os.popen("rm %s -fr" % self.pidfile)
                    pass
            else:
                #开始全场嗅探
                sniff(prn = self.wto_pcap)
        except Exception, err:
            fp = open("/analyzer/log.txt", "a+")
            fp.write(time.strftime(r'%Y.%m.%d_%H:%M',time.localtime(time.time())) + "<single_sniff.run>" + str(err) + "\n")
            fp.close()

    def stop(self,signalnum,handler):
        #异常结束，或者被前台关闭嗅探时，进行文件操作

        dst_dirname = self.dstfile + self.pcapname[0:-5]  # 生成对应包的子包文件夹名字，去掉pcapname的.pcap后缀
        if not os.path.exists(dst_dirname):
            os.system("mkdir %s" % dst_dirname)  # 创建子包文件夹
        os.system("editcap -c 100 -F libpcap %s %s" % (self.filename, dst_dirname + '/easyedu'))  # 进行拆分，将嗅探包文件，拆分到pcap包文件路径下，并加上easyedu前缀
        os.system("mv %s %s" % (self.filename, self.dstfile))  # 将嗅探文件，移到pcap包文件目录下
        if os.path.exists(self.pidfile):
            os.popen("rm %s -fr" % self.pidfile)
            pass
        sys.exit(0)

    def wto_pcap(self, pkt):
        wrpcap(self.filename, pkt, append=True)
        self.pkt_count += 1
        if self.filemaxsize > 0:
            cursize = os.path.getsize(self.filename) / 1024.0 / 1024
            self.curfilesize = cursize
            if cursize >= self.filemaxsize:
                stop(self.pidfile)

#停止
def stop(pidfile):

    if os.path.exists(pidfile):
        try:
            fp = open(pidfile,"r")
            pid = int(fp.read().strip())
            fp.close()
            os.popen("rm -fr %s"%pidfile)
        except IOError,err:
            sys.exit(1)
        if pid != None:
            os.kill(pid,signal.SIGUSR1)
        return pid
    else:
        print "not exsit,not running!\n"

#开启
def start_sniff(*args):

    try:
        one = single_sniff(args[0],args[1],args[2],args[3],args[4],args[5],args[6])
        one.run()
    except Exception,err:
        fp = open("/analyzer/log.txt","a+")
        fp.write(str(err))
        fp.close()

