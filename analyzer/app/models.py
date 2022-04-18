# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


class File_pcap(models.Model):

    name = models.CharField(max_length=64)
    size = models.CharField(max_length=64)
    pkt_counts = models.CharField(max_length=64)
    uploaddate = models.CharField(max_length=64,default=0)


class sniff_Project(models.Model):

    pro_name = models.CharField(unique=True,max_length=64)
    filter = models.CharField(max_length=256)
    pcap_name = models.CharField(max_length=128)
    netcard = models.CharField(max_length=128)
    pkt_counts = models.IntegerField(null=True)
    pcap_size = models.CharField(max_length=32)
    stat = models.IntegerField(default=0)


class Bugs(models.Model):

    name = models.CharField(max_length=64)
    desc = models.CharField(max_length=256)


class Bugs_content(models.Model):

    name = models.ForeignKey(Bugs)
    filter_string = models.TextField()


class Scan_result(models.Model):

    match_hash = models.CharField(max_length=256)
    pcap_name = models.CharField(max_length=256, default="")
    start_time = models.CharField(max_length=256)
    stop_time = models.CharField(max_length=256)
    filter = models.TextField()
    pass

class Repoters(models.Model):

    user_id = models.IntegerField()
    repoter_name = models.CharField(max_length=256, default="")
    repoter_summary = models.TextField(default="")
    pcap_name = models.CharField(max_length=256, default="")
    report_down = models.CharField(max_length=256, default="")
    update_time = models.CharField(max_length=256, default="2016-11-11 11:11")
    pass

