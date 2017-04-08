# -*- coding: utf-8 -*-
# author: rogen
from django.shortcuts import render, render_to_response
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.clickjacking import xframe_options_exempt
from rest_framework.decorators import api_view
from werkzeug.utils import secure_filename
from django.template.loader import render_to_string
from django.http import HttpResponse, HttpResponseRedirect, Http404, StreamingHttpResponse
from func import *
from models import sniff_Project, File_pcap, Bugs, Bugs_content, Repoters, Scan_result
from start_sniff import *
from multiprocessing import Process
from django.core.files import File
import xml.etree.ElementTree as ET
import simplejson, json
import base64
import urllib
import sys
import zipfile
import bs4

reload(sys)
sys.setdefaultencoding('utf-8')

CHLD_PROCESS = {}  # {id1:process_object1,id2:process_object2}
zippath = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
apppath = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = apppath + '/pcapfiles/'
PID_FOLDER = apppath + '/pidfile/'
REPORT_FOLDER = apppath + "/repoters/"

PER_FILE_PKTS = 100
ALLOWED_EXTENSIONS = set(['pcap', 'pcapng', 'cap'])


# 保存用户登录id
@api_view(["GET"])
def login(request, sid):
    if "Chrome" in request.META.get("HTTP_USER_AGENT") or \
                    "chrome" in request.META.get("HTTP_USER_AGENT"):
        request.session["userid"] = int(sid)
        return HttpResponseRedirect("/upload")
    else:
        return render(request, "verify.html", context={"msg": "您所使用的浏览器存在兼容问题，请使用谷歌浏览器访问！"})


# 上传包
@xframe_options_exempt
@csrf_exempt
@api_view(["GET", "POST"])
def upload(request):
    if "Chrome" in request.META.get("HTTP_USER_AGENT") or \
                    "chrome" in request.META.get("HTTP_USER_AGENT"):
        if request.method == 'GET':
            list_file()
            a = {'CapFiles': show_entries()}
            return render(request, 'upload.html', context=a)
        elif request.method == 'POST':
            file = request.FILES['pcapfile']
            if file and allowed_file(file.name):
                filename = secure_filename(file.name)  # 获取安全文件名，仅支持ascii字符
                if os.path.exists(UPLOAD_FOLDER + filename):
                    # print "exists"
                    return HttpResponseRedirect('/upload/', simplejson.dumps({"file": [('The file exists!')]}))
                fp = open(UPLOAD_FOLDER + filename, 'wb+')
                for chunk in file.chunks():
                    fp.write(chunk)
                fp.close()
                p = None
                try:
                    os.mkdir(UPLOAD_FOLDER + filename[0:-5])
                    p = os.popen("editcap -c 100 -F libpcap %s %s" % (UPLOAD_FOLDER + filename, \
                                                                      UPLOAD_FOLDER + filename[0:-5] + '/'))
                except Exception, err:
                    print 'upload error:', str(err)
                size = os.path.getsize(UPLOAD_FOLDER + filename)
                result = (filename, 'PCAP', size)
                return HttpResponseRedirect('/upload/', simplejson.dumps({"files": [result]}))
        else:
            pass
    else:
        return render(request, "verify.html", context={"msg": "您所使用的浏览器存在兼容问题，请使用谷歌浏览器访问！"})


# 下载包
@api_view(["GET"])
def download(request, idstr):
    try:
        id_list = idstr.split(",")
        zipfilelist = []
        for id in id_list[0:-1]:
            id = int(id)
            pcapfile = get_pcap_entries(id)
            filename = pcapfile[0]['filename'].encode("utf8")
            zipfilelist.append(filename)
        zipf = zipfile.ZipFile("pcapfiles.zip", 'w')
        pre_len = len(os.path.dirname(UPLOAD_FOLDER))
        for parent, dirnames, filenames in os.walk(UPLOAD_FOLDER):
            for filename in filenames:
                if filename in zipfilelist:
                    pathfile = os.path.join(parent, filename)
                    arcname = pathfile[pre_len:].strip(os.path.sep)  # 相对路径
                    zipf.write(pathfile, arcname)
        zipf.close()
        fp = open(zippath + "/pcapfiles.zip", "r")
        Fp = File(fp)
        response = StreamingHttpResponse(Fp.chunks())
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = 'attachment;filename="{0}"'.format("pcapfiles.zip")
        return response
    except Exception, err:
        print err


# 刷新包列表
@csrf_exempt
@api_view(["GET"])
def analyze(request, id, num):
    # print "analyze:", request.session["userid"]
    if "Chrome" in request.META.get("HTTP_USER_AGENT") or \
                    "chrome" in request.META.get("HTTP_USER_AGENT"):
        try:
            id = int(id)
            num = int(num) - 1
        except:
            return render(request, "404.html", context={"msg": "您提供了错误的参数！！！"})
        filter = None
        if divdePcap(id):  # 拆包时出错，则返回
            return render(request, "404.html", context={"msg": "您的原始包文件不见了！！！"})
            pass
        pcapfile = getChildrenfile(id, num)  # 获取页码对应的子包文件名
        pcapfile_entries = get_pcap_entries(id)
        details = decode_capture_file(pcapfile, num, filter)
        web = get_web(pcapfile, num)
        dns, dnstable = get_dns(pcapfile)
        filepath = os.path.dirname(pcapfile)
        total = len(os.listdir(filepath))  # 减掉bugs生成的三个目录文件
        ret = {
            "pcapfile": pcapfile_entries[0],
            "details": details,
            "num": num + 1,  # 加上1，使页码显示正确
            "web": web,
            "id": id,
            "dns": dnstable,
            "total": total,
        }
        try:
            return render(request, 'analyze.html', context=ret)
        except Exception, err:
            print "analyze error", str(err)
            details = decode_capture_file(pcapfile, num)
            ret["details"] = details
            return render(request, 'analyze.html', context=ret)
    else:
        return render(request, "verify.html", context={"msg": "您所使用的浏览器存在兼容问题，请使用谷歌浏览器访问！"})


# 获取包细节
@api_view(["GET"])
def packetdetail(request, id, page, num):
    # print "id,page,num",id,page,num
    try:
        id = int(id)
        page = int(page)
        num = int(num) - page * PER_FILE_PKTS;
    except Exception, err:
        return render(request, "404.html", context={"msg": "您提供了错误的参数！！！"})
    pcapfile = getChildrenfile(id, page)
    try:
        num = int(num)
        return HttpResponse(get_packet_detail(pcapfile, num))
    except:
        return 0


# 删除原始包文件以及一些关联内容
@xframe_options_exempt
@api_view(["POST"])
def delete_file(request, id):
    delids = id.split(',')
    for delid in delids:
        try:
            delid = int(delid)
            # 删除本地pcap文件
            mi = File_pcap.objects.get(id=delid)
            name = mi.name
            os.remove(UPLOAD_FOLDER + name)
            os.popen("rm -fr %s" % UPLOAD_FOLDER + name[0:-5])
            mi.delete()
            # 删除mongo的扫描缓存
            list_client = Client()
            list_bugs = list_client.bugs
            list_bugs_info = list_bugs.bugs_info
            mscan_result = Scan_result.objects.all()
            match_hash = []
            for msr in mscan_result:
                if msr.pcap_name == name:
                    if msr.match_hash not in match_hash:
                        match_hash.append(msr.match_hash)
            for m in match_hash:
                list_bugs_info.remove({"keystone": m})
            # 删除scan_result表对应扫描信息
            mscan_result.delete()
            # 删除repoters表对应信息
            mrepoter = Repoters.objects.all()
            reporter_name = []
            for mr in mrepoter:
                if mr.pcap_name == name[0:-5]:
                    if request.session["userid"] == mr.user_id:
                        reporter_name.append(mr.repoter_name)
                        mr.delete()
                pass
            # 删除服务器上的repoter报告文件
            for rn in reporter_name:
                cmd = "rm %s -fr" % (REPORT_FOLDER + rn)
                os.popen(cmd)
                pass
        except Exception, err:
            print 'delete_file error:', str(err)
    return HttpResponseRedirect("../../upload/")


# 新增嗅探项目
@xframe_options_exempt
@api_view(["PUT", "GET", "POST"])
def getParameters(request):
    '''
    1、获取sniff可能需要的参数
    2、获取额外添加的各种漏洞规则
        后台以字典形式得到：
            ‘规则名字’:['规则特征字符1'，'规则特征字符2','规则特征字符3',....]
    '''
    if "Chrome" in request.META.get("HTTP_USER_AGENT") or \
                    "chrome" in request.META.get("HTTP_USER_AGENT"):
        ret = {
            'code': 1,
            'params': None,
            'msg': 'No Project',
            'data_err': 0,

        }
        if request.method == 'POST':

            try:
                curtime = time.strftime(r'%H%M%S', time.localtime(time.time()))
                params = request.POST
                pro_name = params["pro_name"]

                pro_name = urllib.unquote(pro_name)
                pcapfilename = ''
                if '.pcap' not in pcapfilename:
                    pcapfilename = curtime + '.pcap'
                netcard = params['netcard']
                filter = params['filter']
                try:
                    pkt_counts = int(params['pkt_counts'])
                    pcap_size = int(params['pcap_size'])
                except Exception, err:
                    ret['data_err'] = 1
                    ret['params'] = show_pro_entries()
                    ret['Iface'] = getNetwork()
                    if ret['params'] == []:
                        ret['code'] = 0
                    ret['msg'] = '请完善数据！'
                    return HttpResponse(simplejson.dumps(ret))
                    # print "proname:%s\npcapfilename:%s\nnetcard:%s\nfilter:%s\npkt_counts:%s\npcap_size:%s\n" % \
                    #       (pro_name,pcapfilename,netcard,filter,pkt_counts,pcap_size)
            except Exception, err:
                ret['code'] = 0
                ret['msg'] = str(err)
                print "getParameters error:", str(err)
                return HttpResponse(simplejson.dumps("bad request params"))
            if pro_name is '' or pcapfilename is '' or netcard is '':
                ret['data_err'] = 1
                ret['params'] = show_pro_entries()
                ret['Iface'] = getNetwork()
                if ret['params'] == []:
                    ret['code'] = 0
                ret['msg'] = '请完善数据！'
                return HttpResponse(simplejson.dumps(ret))
            else:
                try:
                    mc = sniff_Project.objects.all()
                    mc.create(pro_name=pro_name, pcap_name=pcapfilename, netcard=netcard, filter=filter, \
                              pkt_counts=pkt_counts, pcap_size=pcap_size, stat=0)
                    mid = sniff_Project.objects.get(pro_name=pro_name)
                    mid.pcap_name = mid.id + "_" + pcapfilename
                    print "pcap_name:", mid.pcap_name
                    mid.save()
                except Exception, err:
                    if 'Duplicate' in str(err):
                        mf = sniff_Project.objects.get(pro_name=pro_name)
                        mf.pcap_name = pcapfilename
                        mf.filter = filter
                        mf.pkt_counts = pkt_counts
                        mf.pcap_size = pcap_size
                        mf.netcard = netcard
                        mf.stat = 0
                        mf.save()
                    else:
                        return HttpResponse(str(err))
            ret['params'] = show_pro_entries()
            ret['Iface'] = getNetwork()
            bpf_config = apppath + "/app01_config"
            ret["bpf_filter"] = getConfig(bpf_config)["bpf_filter"]
            if ret['params'] == []:
                ret['code'] = 0
            return render(request, 'prolist.html', context=ret)
        elif request.method == 'PUT':
            # strs = [" ", "%", "&", "#", "!", "@", "^", "(", ")", "[", "]", "{", "}", "~", "+", "=", "-", "_", ".", ",",";", "|","。","，","；","”","：","",""]
            strs = " [`~!@#$^&*()=|{}':;',\\[\\].<>/?~！@#￥……&*（）——|{}【】‘；：”“'。，、？]"
            pro_name = request.body.split('=')[1]
            pro_name = urllib.unquote(pro_name)
            mp = sniff_Project.objects.filter(pro_name=pro_name)
            if mp:
                return HttpResponse("项目已存在！！！")
            for sb in pro_name:
                if sb in strs or sb == " ":
                    return HttpResponse("非法字符！！！")
            return HttpResponse("")

        else:  # 处理GET方法
            ret['params'] = show_pro_entries()
            ret['Iface'] = getNetwork()
            bpf_config = apppath + "/app01_config"
            ret["bpf_filter"] = getConfig(bpf_config)["bpf_filter"]
            if ret['params'] == []:
                ret['code'] = 0
            return render(request, 'prolist.html', context=ret)
    else:
        return render(request, "verify.html", context={"msg": "您所使用的浏览器存在兼容问题，请使用谷歌浏览器访问！"})


# 列出漏洞规则
@xframe_options_exempt
@api_view(["GET"])
def getBugs(request):
    if "Chrome" in request.META.get("HTTP_USER_AGENT") or \
                    "chrome" in request.META.get("HTTP_USER_AGENT"):
        ret = {
            'sql_code': 1,
            'xss_code': 1,
            'other_code': 1,
            'msg': 'No Project',
        }
        sql_obj = Bugs.objects.get(name="SQL_Injection")
        xss_obj = Bugs.objects.get(name="XSS")
        other_obj = Bugs.objects.get(name="Other")
        sql_injection = sql_obj.bugs_content_set.all()
        xss = xss_obj.bugs_content_set.all()
        other = other_obj.bugs_content_set.all()

        if sql_injection:
            # ret["sql_injection"] = sql_list
            ret["sql_injection"] = sql_injection
            ret["sql_len"] = len(sql_injection)
        else:
            ret["sql_code"] = 0
        if xss:
            ret["xss"] = xss
            ret["xss_len"] = len(xss)
        else:
            ret["xss_code"] = 0
        if other:
            ret["other"] = other
            ret["other_len"] = len(other)
        else:
            ret["other_code"] = 0
        # idstr = ""
        # for i in range(313,433):
        #     idstr += str(i) + ","
        # print "\n".join(get_filter(idstr)["XSS"])
        # print len(get_filter(idstr)["XSS"])
        return render(request, "bugs.html", context=ret)
    else:
        return render(request, "verify.html", context={"msg": "您所使用的浏览器存在兼容问题，请使用谷歌浏览器访问！"})


# 控制sniff嗅探
@xframe_options_exempt
@api_view(["GET"])
def sniffer_controller(request, id):
    # print 'get####',dir(request)
    global CHLD_PROCESS
    try:
        id = int(str(id))
        mp = sniff_Project.objects.get(id=id)
    except Exception, err:
        return HttpResponse("No Attacking,Warnnig!")
    curtime = str(time.time())
    curtime = curtime.split('.')[0] + curtime.split('.')[1]
    pcap_name = str(id) + "_" + curtime + ".pcap"  # 给每个包文件名加上时间戳，确保多次开启项目，后台嗅探文件的名字不冲突
    filter = mp.filter
    pkt_counts = mp.pkt_counts
    pcap_size = mp.pcap_size
    netcard = mp.netcard
    netcard = netcard.split(' ')[0]
    # print "sniffer_controller:",len(pro_name.encode("utf-8")),len(pro_name)
    pidname = PID_FOLDER + base64.urlsafe_b64encode(mp.pro_name.encode("utf-8")).strip()
    if mp.stat:
        if os.path.exists(pidname):
            pid = stop(pidname)
            os.waitpid(pid, 0)  # 回收小僵尸
        mp.stat = 0
        mp.save()
        flag = "关闭"
    elif mp.stat == 0:
        one_p = Process(target=start_sniff, args=(
        pidname, netcard.encode("utf-8"), pcap_name.encode("utf-8"), UPLOAD_FOLDER, filter.encode("utf-8"), pkt_counts,
        pcap_size.encode("utf-8"),))
        try:
            one_p.start()
            CHLD_PROCESS[str(mp.id)] = one_p  # 将嗅探项目id，和后台嗅探子进程相关联
        except Exception, err:
            print "sniffer_control:one_p.start() error", err
        mp.stat = 1
        mp.save()
        flag = "开启"
    else:
        pass
        # print mp.stat
    return HttpResponse(flag)


# 保存SQL_Injection漏洞规则
@api_view(["POST"])
def saveSQL(request):
    try:
        params = request.POST
        filter_string = params["filter_string"]
        # filter_reg = params["filter_reg"]
        bugs = Bugs.objects.get(name="SQL_Injection")
        bug_content = Bugs_content.objects.all()
        bug_content.create(name=bugs, filter_string=filter_string)
    except Exception, err:
        print "saveSQL error:", str(err)
    return HttpResponseRedirect("/bugs/")


# 保存XSS漏洞规则
@api_view(["POST"])
def saveXSS(request):
    try:
        params = request.POST
        filter_string = params["filter_string"]
        # filter_reg = params["filter_reg"]
        bugs = Bugs.objects.get(name="XSS")
        bug_content = Bugs_content.objects.all()
        bug_content.create(name=bugs, filter_string=filter_string)
    except Exception, err:
        print "saveXSS error:", str(err)
    return HttpResponseRedirect("/bugs/")
    pass


# 保存用户自定义漏洞规则
@api_view(["POST"])
def saveOther(request):
    try:
        params = request.POST
        filter_string = params["filter_string"]
        # filter_reg = params["filter_reg"]
        bugs = Bugs.objects.get(name="Other")
        bug_content = Bugs_content.objects.all()
        bug_content.create(name=bugs, filter_string=filter_string)
    except Exception, err:
        print "saveOther err:", str(err)
    return HttpResponseRedirect("/bugs/")
    pass


# 删除漏洞规则
@api_view(["GET"])
def delBugs(request, id):
    delids = id.split(',')
    for delid in delids:
        try:
            delid = int(delid)
        except:
            return render(request, "404.html", context={"msg": "您提供了错误的参数！！！"})
        mi = Bugs_content.objects.get(id=delid)
        mi.delete()
    return HttpResponseRedirect("../../bugs/")


# 删除项目
@api_view(["GET"])
def delPro(request, id):
    delids = id.split(',')
    for delid in delids:
        try:
            delid = int(delid)
        except:
            return render(request, "404.html", context={"msg": "您提供了错误的参数！！！"})
        mi = sniff_Project.objects.get(id=delid)
        if mi:
            pcap_name = UPLOAD_FOLDER + mi.pcap_name
            pcap_dir = pcap_name[0:-5]
            os.system("rm -fr %s %s" % (pcap_dir, pcap_name))
        mi.delete()
    return HttpResponseRedirect("../../options/")


# 扫描
@api_view(["GET", "POST"])
def pcapScan(request, id, num):
    '''
    前台数据：
        一个post表单的格式：
                1、所选择的漏洞规则名称，及对应的漏洞规则id
                2、设置的时间期限
    :param request:
    :return:
    '''
    SCAN_PAGER = 100
    page_id = id
    list_client = Client()
    list_bugs = list_client.bugs
    list_bugs_info = list_bugs.bugs_info
    page_num = int(num)
    if request.method == "POST":
        params = request.POST
        bugs_id = params["bugs_id"]  # id = 1,2,3,4,5
        start = params["start_time"].replace("/", "-").replace(" ", "time")
        if params["stop_time"] == "false":
            stop = "false"
        else:
            stop = params["stop_time"].replace("/", "-").replace(" ", "time")
        id = params["id"]
        bugsfile = getChildrenfile(id)
        mscan = Scan_result.objects.all()
        match = bugsfile + str({"start_time": start, "stop_time": stop}) + str(get_filter(bugs_id))
        match_hash = hashlib.md5(match).hexdigest()
        if not Scan_result.objects.filter(match_hash=match_hash):
            f = json.dumps(get_filter(bugs_id))
            # print f
            mscan.create(match_hash=str(match_hash), pcap_name=bugsfile + ".pcap", start_time=start, stop_time=stop,
                         filter=f)
        request.session["match_hash"] = match_hash
        content_num = list_bugs_info.count({"keystone": match_hash})  # 查找数据库中共有多少条数据
        if content_num != 0:
            if content_num > SCAN_PAGER:  # 大于SCAN_PAGER开启分页
                page_total = content_num / SCAN_PAGER
                if content_num % SCAN_PAGER:
                    page_total += 1
                first = (page_num - 1) * SCAN_PAGER
                last = page_num * SCAN_PAGER
                match_ret = list_bugs_info.find(
                    {"keystone": match_hash, "content_num": {"$gte": first}, "content_num": {"$lte": last}})
                ret = {
                    "mongo_bugs_data": match_ret,
                    "code": 1,
                    "recoder": content_num,
                    "curpage": page_num,
                    "page_total": page_total,
                    "kkpager_flag": 1,
                    "id": page_id,
                    "msg": match_hash  # "successfully",
                }  #
                response = render_to_response('scanresult.html', context=ret)
                try:
                    for i in range(1, page_total + 1):
                        key = str(i) + "_key"
                        response.set_cookie(key, "", path="/scandetail/" + str(page_id) + "/")
                        response.set_cookie("#ABC", match_hash, path="/scandetail/" + str(page_id) + "/")
                        pass
                except Exception, err:
                    print "pcapScan 522 error:", err

            else:  # 不分页
                match_ret = list_bugs_info.find({"keystone": match_hash})
                ret = {
                    "mongo_bugs_data": match_ret,
                    "code": 1,
                    "recoder": content_num,
                    "curpage": page_num,
                    "kkpager_flag": 0,
                    "id": page_id,
                    "msg": "successfully",
                }
                response = render_to_response('scanresult.html', context=ret)
                try:
                    response.set_cookie("#ABC", match_hash, path="/scandetail/" + str(page_id) + "/")
                    response.set_cookie(str(page_num) + "_key", "", path="/scandetail/" + str(page_id) + "/")
                except Exception, err:
                    print "pcapScan 540 error:", err
                    pass

            return response
        else:
            filter_Bugs(bugsfile, start, stop, bugs_id)  # 陷入进程等待中，等待最后一个线程结束，继续执行主线程
            content_num = list_bugs_info.count({"keystone": match_hash})  # 查找数据库中共有多少条数据
            if content_num != 0:  # 数据库中没有备份，尝试从新扫描，扫描到返回数据
                if content_num > SCAN_PAGER:  # 大于SCAN_PAGER开启分页
                    page_total = content_num / SCAN_PAGER
                    if content_num % SCAN_PAGER:
                        page_total += 1
                    first = (page_num - 1) * SCAN_PAGER
                    last = page_num * SCAN_PAGER
                    match_ret = list_bugs_info.find(
                        {"keystone": match_hash, "content_num": {"$gte": first}, "content_num": {"$lt": last}})
                    ret = {
                        "mongo_bugs_data": match_ret,
                        "match_hash": str(match_hash),
                        "code": 1,
                        "recoder": content_num,
                        "curpage": page_num,
                        "page_total": page_total,
                        "kkpager_flag": 1,
                        "id": page_id,
                        "msg": match_hash,  # "successfully",
                    }  #
                    response = render_to_response('scanresult.html', context=ret)
                    try:
                        for i in range(1, page_total + 1):
                            key = str(i) + "_key"
                            response.set_cookie(key, "", path="/scandetail/" + str(page_id) + "/")
                            response.set_cookie("#ABC", match_hash, path="/scandetail/" + str(page_id) + "/")
                            pass
                    except Exception, err:
                        print "pcapScan 575 error:", err

                else:  # 不分页
                    match_ret = list_bugs_info.find({"keystone": match_hash})
                    ret = {
                        "mongo_bugs_data": match_ret,
                        "match_hash": str(match_hash),
                        "code": 1,
                        "recoder": content_num,
                        "curpage": page_num,
                        "id": page_id,
                        "kkpager_flag": 0,
                        "content_num_flag": 0,
                        "msg": "successfully",
                    }
                    response = render_to_response('scanresult.html', context=ret)
                    try:
                        response.set_cookie("#ABC", match_hash, path="/scandetail/" + str(page_id) + "/")
                        response.set_cookie(str(page_num) + "_key", "", path="/scandetail/" + str(page_id) + "/")
                    except Exception, err:
                        print err
                return response
            else:  # 未扫描到数据，说明此种扫描条件不能发现漏洞包
                ret = {
                    "code": 0,
                    "msg": "Nothing",
                }
                return render(request, "scanresult.html", context=ret)
    elif request.method == "GET":
        try:
            try:
                match_hash = request.session["match_hash"]
            except:
                return render(request, "404.html", context={"msg": "您提供了错误的参数！！！"})
            content_num = list_bugs_info.count({"keystone": match_hash})  # 查找数据库中共有多少条数据
            if content_num != 0:
                if content_num > SCAN_PAGER:  # 大于SCAN_PAGER开启分页
                    page_total = content_num / SCAN_PAGER
                    if content_num % SCAN_PAGER:
                        page_total += 1
                    first = (page_num - 1) * SCAN_PAGER
                    last = page_num * SCAN_PAGER
                    match_ret = list_bugs_info.find(
                        {"keystone": match_hash, "content_num": {"$gte": first, "$lte": last}})
                    # print "get page_id:",page_id
                    ret = {
                        "match_hash": str(match_hash),
                        "mongo_bugs_data": match_ret,
                        "code": 1,
                        "id": page_id,
                        "recoder": content_num,
                        "curpage": page_num,
                        "page_total": page_total,
                        "kkpager_flag": 1,
                        "msg": "successfully",
                    }  #
                else:  # 不分页
                    match_ret = list_bugs_info.find({"keystone": match_hash})
                    ret = {
                        "mongo_bugs_data": match_ret,
                        "match_hash": match_hash,
                        "code": 1,
                        "id": page_id,
                        "recoder": content_num,
                        "curpage": page_num,
                        "kkpager_flag": 0,
                        "msg": "successfully",
                    }
                return render(request, "scanresult.html", context=ret)
            else:
                content_num = list_bugs_info.count({"keystone": match_hash})  # 查找数据库中共有多少条数据
                if content_num != 0:  # 数据库中没有备份，尝试从新扫描，扫描到返回数据
                    if content_num > SCAN_PAGER:  # 大于SCAN_PAGER开启分页
                        page_total = content_num / SCAN_PAGER
                        if content_num % SCAN_PAGER:
                            page_total += 1
                        first = (page_num - 1) * SCAN_PAGER
                        last = page_num * SCAN_PAGER
                        match_ret = list_bugs_info.find(
                            {"keystone": match_hash, "content_num": {"$gte": first}, "content_num": {"$lte": last}})
                        # print "####",match_ret
                        ret = {
                            "match_hash": match_hash,
                            "mongo_bugs_data": match_ret,
                            "code": 1,
                            "recoder": content_num,
                            "curpage": page_num,
                            "id": page_id,
                            "page_total": page_total,
                            "kkpager_flag": 1,
                            "msg": "successfully",
                        }  #
                    else:  # 不分页
                        match_ret = list_bugs_info.find({"keystone": match_hash})
                        ret = {
                            "mongo_bugs_data": match_ret,
                            "match_hash": str(match_hash),
                            "code": 1,
                            "id": page_id,
                            "kkpager_flag": 0,
                            "recoder": content_num,
                            "content_num_flag": 0,
                            "msg": "successfully",
                        }
                    return render(request, "scanresult.html", context=ret)
                else:  # 未扫描到数据，说明此种扫描条件不能发现漏洞包
                    ret = {
                        "code": 0,
                        "msg": "Nothing",
                    }
                    return render(request, "scanresult.html", context=ret)
        except Exception, err:
            print "error:", str(err)
            pass

    else:
        pass


# 扫描配置
@api_view(["GET"])
def pcapSelect(request, id):
    '''
    1、前台upload页面点击扫描按键，跳转到扫描页面
    2、扫描<<页面抬头>>展示包的一些基本信息：
        size， pkts, start_time, stop_time, 平均每秒包数：pkts / (stop_time - start_time)
    3、页面竖向分3大块：
            《基本信息》
            《扫描选项》：
                    《规则勾选》
                    《时间截取》
                            按钮：开始扫描 post data=id,start_time,stop_time  url:/scan/pcapscan/
            《扫描结果》：
                    一个列表删选框：可以根据td进行删选(包号増序，降序等)
                    《列表》：序号、规则、包号、协议、内容、编辑
                    按钮：生成报告
    :param request:
    :return:
    '''
    print "pcapSelect"
    try:
        id = int(id)
        ret = getScanfileinfo(id)
        ret["sql_code"] = 1
        ret["xss_code"] = 1
        ret["other_code"] = 1
        ret["msg"] = "Nothing"
        ret["code"] = 0
        pname = getChildrenfile(id).encode("utf-8")
        if Repoters.objects.all().filter(pcap_name=pname):
	    print "if"
            ret["code"] = 1
            sm = show_reporter(pname)
            repoter_list = []
            for i in sm:
		print "for1"
                tmp = {}
                tmp["reporter_name"] = i["reporter_name"].split("_")[0]
                tmp["reporter_summary"] = simplejson.loads(i["reporter_summary"])
                filter = tmp["reporter_summary"]["results_summary"]["match_rule"]
                filter = simplejson.loads(urllib.unquote(filter))
                rule = ""
                for f in filter.items():
		    print "for2"
                    rule += ",".join(f[1]) + "<br>"
                tmp["id"] = i["id"]
                tmp["time"] = i["time"]
                tmp["rule"] = rule
                tmp["report_down"] = i["report_down"]
                repoter_list.append(tmp)
            ret["repoter"] = repoter_list
            pass

        sql_obj = Bugs.objects.get(name="SQL_Injection")
        xss_obj = Bugs.objects.get(name="XSS")
        other_obj = Bugs.objects.get(name="Other")
        sql_injection = sql_obj.bugs_content_set.all()
        xss = xss_obj.bugs_content_set.all()
        other = other_obj.bugs_content_set.all()

        if sql_injection:
            ret["sql_injection"] = sql_injection
            ret["sql_len"] = len(sql_injection)
        else:
            ret["sql_code"] = 0
        if xss:
            ret["xss"] = xss
            ret["xss_len"] = len(xss)
        else:
            ret["xss_code"] = 0

        if other:
            ret["other"] = other
            ret["other_len"] = len(other)
        else:
            ret["other_code"] = 0
    except Exception, err:
        print "pcapSelect error:", str(err)
        pass
    return render(request, "scan.html", context=ret)


# 获取bpf提示
@api_view(["GET"])
def getBPF(request):
    bpf_config = apppath + "/bpf_config"
    ret = getConfig(bpf_config)["bpf_filter"]
    return render(request, "scan.html", context=ret)
    pass


# 提示报告信息
@api_view(["GET"])
def willRepoter(request, id):
    params = request.COOKIES
    # print params
    content_num_list = []
    match_hash = ""
    list_client = Client()
    list_bugs = list_client.bugs
    list_bugs_info = list_bugs.bugs_info
    for i in params.items():
        if i[1] != "":
            if "key" in i[0]:
                tmp = urllib.unquote(i[1]).split(",")[0:-1]
                content_num_list.extend(tmp)
            elif "#ABC" == i[0]:
                match_hash = i[1]
            else:
                pass

    scan_num = list_bugs_info.count({"keystone": match_hash})
    select_num = len(content_num_list)
    repoter_name = getChildrenfile(id) + "_repoter.html"
    ret = "<p>报告名字: <span style=color:green;font-weight:bold;>%s</span>;\
    <br>此次共扫描出漏洞包<span style=color:red;font-weight:bold;>%d</span>个;\
    <br>选取生成报告的漏洞包<span style=color:red;font-weight:bold;>%d</span>个.</p>" % \
          (request.session["repoter_name"], scan_num, select_num)
    return HttpResponse(simplejson.dumps(ret, ensure_ascii=False))


# 拉去报告列表
@api_view(["GET"])
def gerRepoter(request, id):
    params = request.COOKIES
    # print params
    content_num_list = []
    match_hash = ""
    list_client = Client()
    list_bugs = list_client.bugs
    list_bugs_info = list_bugs.bugs_info
    try:
        has_userid = request.session["userid"]
    except:
        err = {"msg": "认证已过期，请从数据分析字平台重新登录"}
        return render(request, "404.html", err)
    for i in params.items():
        if i[1] != "":
            if "key" in i[0]:
                tmp = urllib.unquote(i[1]).split(",")[0:-1]
                content_num_list.extend(tmp)
            elif "#ABC" == i[0]:
                match_hash = i[1]
            else:
                pass
    desc = ""
    netcard = ""
    pcapfilename = getChildrenfile(id).split("_")[0]
    if sniff_Project.objects.filter(pro_name=pcapfilename):
        ps = sniff_Project.objects.get(pro_name=pcapfilename)
        netcard = ps.netcard
        pass
    if netcard != "":
        host_ip = netcard.split(":")[0]
        host_hard = netcard.split(":")[1]
    else:
        host_ip = "外部引入"
        host_hard = "外部引入"

    all_pack = File_pcap.objects.get(id=id).pkt_counts
    match_pack = list_bugs_info.count({"keystone": match_hash})

    if Scan_result.objects.filter(match_hash=match_hash):
        ps = Scan_result.objects.get(match_hash=match_hash)
        filter = ps.filter

    tmp = []
    for i in content_num_list:
        tmp.append(int(i))
    tmp.sort()
    content_num_list = tmp

    # 处理用户选中项与数据库做匹配，选择最快方案
    counter = 0
    final_list = []
    report_down = getConfig(apppath + "/app01_config")["repoter"][0]["report_down"] + "repoterdown/"
    example = {}
    for n in content_num_list:
        final = {}
        counter += 1
        # print list_bugs_info.count({"keystone" : match_hash,"content_num" : int(n)})
        bi = list_bugs_info.find({"keystone": match_hash, "content_num": int(n)})
        bi = bi[0]
        if counter == 1:
            example["name"] = str(bi["packet_num"]) + "-" + str(bi["bugs_name"])
            example["desc"] = bi["content"]
            # example["report_down"] = report_down
        name = str(bi["packet_num"]) + "-" + str(bi["bugs_name"])
        desc = bi["content"]
        final["name"] = name
        final["desc"] = desc
        final_list.append(final)

    ret_summary = {
        'host_ip': host_ip,
        'host_hard': host_hard,
        'results_summary': {
            'all_pack': all_pack,
            'match_pack': match_pack,
            'select_pack': counter,
            'match_rule': filter,
            'report_down': report_down,
        },
        'example': [example],
    }
    filter = simplejson.loads(urllib.unquote(filter))
    rule = ""
    for f in filter.items():
        rule += ",".join(f[1]) + "<br>"
    ret_final = {
        'host_ip': host_ip,
        'host_hard': host_hard,
        'results_summary': {
            'all_pack': all_pack,
            'match_pack': match_pack,
            'match_rule': rule,
        },
        'example': final_list,
    }
    ret = {"scan_repo": ret_final}
    # 将概要描述入库
    repoter_name = request.session["repoter_name"] + "_" + str(request.session["userid"])
    mr = Repoters.objects.all()
    mr.create(user_id=request.session["userid"], repoter_name=repoter_name \
              , repoter_summary=simplejson.dumps(ret_summary), pcap_name=pcapfilename, \
              update_time=time.strftime(r'%Y.%m.%d_%H:%M', time.localtime(time.time())))
    report = mr.get(user_id=request.session["userid"], repoter_name=repoter_name)
    report_id = report.id
    ret_summary["results_summary"]["report_down"] = report_down + str(report_id) + "/"
    # ret_summary["example"][0]["report_down"] = report_down + str(report_id) + "/"
    report.repoter_summary = simplejson.dumps(ret_summary)
    report.report_down = report_down + str(report_id) + "/"
    report.save()
    # 生成报告文件

    staic_html = REPORT_FOLDER + repoter_name
    if not os.path.exists(staic_html):
        cont = render_to_string(template_name='repo_tem.html', context=ret)
        with open(staic_html, 'w') as static_file:
            static_file.write(cont)
            static_file.close()
    return HttpResponse("scan/%s/" % str(id))


@api_view(["GET"])
def repoterDownload(request, id):
    try:
        id = int(id)
        mr = Repoters.objects.all()
        if mr.filter(id=id):
            for f in show_repodown_entries(id):
                name = f["name"]
                fp = open(REPORT_FOLDER + name, 'r')
                Fp = File(fp)
                response = StreamingHttpResponse(Fp.chunks())
                response['Content-Type'] = 'application/octet-stream'
                response['Content-Disposition'] = 'attachment;filename="{0}"'.format(name.split("_")[0] + ".html")
                return response
        else:
            return HttpResponse("不规则或已删除的报告")
    except Exception, err:
        return HttpResponse("")


@api_view(["GET"])
def repoterList(request, id):
    try:
        id = int(id)
        mr = Repoters.objects.all()
        if mr.filter(user_id=id):
            return HttpResponse(simplejson.dumps(show_reporter_entries(id)))
            pass
        else:
            return HttpResponse([])
        pass
    except Exception, err:
        print "repoterList error:", err
    pass


# 获取报告信息
@api_view(["GET"])
def repoterInfo(request, id):
    try:
        id = int(id)
        mr = Repoters.objects.all()
        if mr.filter(id=id):
            return HttpResponse(simplejson.dumps(show_reporterinfo_entries(id)[0]))
            pass
        else:
            return HttpResponse([])
        pass
    except Exception, err:
        print "repoterInfo error:", err
    pass


# 附加查询
@api_view(["GET"])
def repoterInfonull(request):
    return HttpResponse([])
    pass


# 检验报告名
@api_view(["POST"])
def repoterName(request):
    # print request.POST
    try:
        flag = "false"
        params = request.POST
        userid = request.session["userid"]
        repoter_name = params["name"]
        strs = ["%", "&", "#", "!", "@", "^", "(", ")", "[", "]", "{", "}", "~", "+", "=", "-", "_", ".", ",", ";", "|"]
        for s in strs:
            if s in repoter_name:
                return HttpResponse("warnning")
        mr = Repoters.objects.all()
        if mr.filter(user_id=userid):
            name = repoter_name + "_" + str(userid)
            if mr.filter(repoter_name=name):
                flag = "false"
            else:
                flag = "true"
                request.session["repoter_name"] = repoter_name
            pass
        else:
            request.session["repoter_name"] = repoter_name
            flag = "true"
        pass
    except Exception, err:
        print "repoterName error:", err
    return HttpResponse(flag)


# 删除报告
@api_view(["POST"])
def delReport(request):
    params = request.POST
    try:
        repo_id = params["repo_id"]
        repo_id_list = repo_id.split(",")
        mr = Repoters.objects.all()
        for ri in repo_id_list:
            if ri != "":
                mdel = mr.get(id=int(ri))
                mdel.delete()
            pass
        pass
    except Exception, err:
        print "delRepoter:", err
    return HttpResponse("")


# 查看bpf规则
@api_view(["GET"])
def bpfLook(request):
    try:
        return render(request, "bpfall.html")
    except Exception, err:
        print "bpfLook error:", err

    pass


# 刷新嗅探项目状态
@api_view(["GET"])
def flushSniff(request, id):
    global CHLD_PROCESS
    try:
        id_list = str(id).split(",")
        for i in id_list:
            mf = sniff_Project.objects.filter(id=int(i))
            if not mf:
                return HttpResponseRedirect('/options')
        for ip in CHLD_PROCESS.keys():
            for i2 in id_list:
                if str(i2) == ip:

                    if not CHLD_PROCESS[ip].is_alive():
                        mg = sniff_Project.objects.get(id=int(i2))
                        mg.stat = 0
                        mg.save()
    except Exception, err:
        print "flushSniff error", str(err)
    return HttpResponseRedirect('/options')
    pass


# 校验用户输入的嗅探数据
@api_view(["POST"])
def sniffVerify(request):
    params = request.POST
    flag = "true"
    try:
        filter = str(params["filter"])
        netcard = str(params["netcard"]).split(":")[0].strip()

    except Exception, err:
        print "sniffVerify key errors:", err

    if "virbr" in netcard:
        flag = "device_err"
    try:
        test_filter = sniff(filter=filter, count=1)
        pass
    except Exception, err:

        if "Filter parse error" in err:
            flag = "filter_err"

    return HttpResponse(flag)


@api_view(["GET"])
def verify(request):
    if "Firefox" in request.META.get("HTTP_USER_AGENT"):
        return HttpResponse("false")
    else:
        return HttpResponse("ture")
    pass


def _saveSQL(params):
    try:
        filter_string = params
        # filter_reg = params["filter_reg"]
        bugs = Bugs.objects.get(name="SQL_Injection")
        bug_content = Bugs_content.objects.all()
        if bug_content.filter(filter_string=filter_string):
            pass
        else:
            bug_content.create(name=bugs, filter_string=filter_string)
    except Exception, err:
        print "saveSQL error:", str(err)
    pass

def _saveXSS(params):
    try:
        filter_string = params
        # filter_reg = params["filter_reg"]
        bugs = Bugs.objects.get(name="XSS")
        bug_content = Bugs_content.objects.all()
        if bug_content.filter(filter_string=filter_string):
            pass
        else:
            bug_content.create(name=bugs, filter_string=filter_string)
    except Exception, err:
        print "saveXSS error:", str(err)
    pass

@api_view(["GET"])
def bugsinsert(request):
    vmm_xml_path = os.path.abspath(os.path.curdir) + "/payloads/"
    pathlist = [vmm_xml_path + i for i in os.listdir(vmm_xml_path)]
    print pathlist
    rootlist = [ET.parse(pathone) for pathone in pathlist]
    roottest = [root.findall('test') for root in rootlist]
    path = []
    for root in roottest:
        path.extend(["#" if disk.find("request").find("payload").text == None else disk.find("request").find("payload").text for disk in root])

    while path.count("#"):
        path.remove("#")

    for p in path:
        _saveSQL(p)

    return HttpResponseRedirect("/bugs")


@api_view(["GET"])
def xssinsert(request):
    path = os.path.abspath(os.path.curdir) + "/app01/payloads/xss.html"
    fp = open(path, 'r')
    soup = bs4.BeautifulSoup(fp,"html.parser")
    result = soup.find_all('pre')
    result = [str(i.text) for i in result]
    for r in result:
        _saveXSS(r)
    # for r in result:
    #     print type(r)
    return HttpResponseRedirect("/bugs")

