# -*- coding: utf-8 -*-
from django.conf.urls import url,include
from django.contrib import admin
import views

urlpatterns = [

    url(r'^login/(?P<sid>\d+)/$', views.login),

    url(r'^upload$', views.upload),
    url(r'^upload/$',views.upload),

    url(r'^options$',views.getParameters),
    url(r'^options/$', views.getParameters),

    url(r'^bugs/$',views.getBugs),
    url(r'^bugsinsert/$', views.bugsinsert),
    url(r'^xssinsert/$', views.xssinsert),
    url(r'^bugs/sql/$',views.saveSQL),
    url(r'^bugs/xss/$',views.saveXSS),
    url(r'^bugs/other/$',views.saveOther),
    # url(r'^bugslist/$',views.listBugs),#生成报告,参数pcap文件名字，返回漏洞名称，数量


    url(r'^analyze/(?P<id>\d+)/(?P<num>.+)/$',views.analyze),

    url(r'^scan/(?P<id>\d+)/$',views.pcapSelect),
    url(r'^scandetail/(?P<id>\d+)/(?P<num>\d+)/$',views.pcapScan),
    url(r'^scandetail/(?P<id>\d+)/info/$',views.willRepoter),
    url(r'^scandetail/(?P<id>\d+)/repoter/$',views.gerRepoter),

    url(r"^bpffilter/$",views.bpfLook),
    url(r"^flushsniff/(?P<id>.+)/$",views.flushSniff),
    url(r"^sniffverify/$",views.sniffVerify),

    url(r'^download_pcap/(?P<idstr>.+)/$',views.download),
    url(r'^repoterdown/(?P<id>\d+)/$', views.repoterDownload),
    url(r'^repoterlist/(?P<id>\d+)/$',views.repoterList),
    url(r'^repoterinfo/(?P<id>\d+)/$',views.repoterInfo),
    url(r'^repoterinfo/$',views.repoterInfonull),
    url(r'^repoterinfo/name/$',views.repoterName),

    url(r'^delete/(?P<id>.+)/$',views.delete_file),
    url(r'^delbugs/(?P<id>.+)/$', views.delBugs),
    url(r'^delpro/(?P<id>.+)/$', views.delPro),
    url(r"^delrepo/$", views.delReport),

    url(r'^packetdetail/(?P<id>\d+)/(?P<page>\d+)/(?P<num>\d+)$',views.packetdetail),

    url(r'^control/(?P<id>\d+)/$',views.sniffer_controller),


]
