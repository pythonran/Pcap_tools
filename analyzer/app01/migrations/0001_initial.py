# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-04-07 17:26
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Bugs',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64)),
                ('desc', models.CharField(max_length=256)),
            ],
        ),
        migrations.CreateModel(
            name='Bugs_content',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('filter_string', models.TextField()),
                ('name', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app01.Bugs')),
            ],
        ),
        migrations.CreateModel(
            name='File_pcap',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64)),
                ('size', models.CharField(max_length=64)),
                ('pkt_counts', models.CharField(max_length=64)),
                ('uploaddate', models.CharField(default=0, max_length=64)),
            ],
        ),
        migrations.CreateModel(
            name='Repoters',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.IntegerField()),
                ('repoter_name', models.CharField(default='', max_length=256)),
                ('repoter_summary', models.TextField(default='')),
                ('pcap_name', models.CharField(default='', max_length=256)),
                ('report_down', models.CharField(default='', max_length=256)),
                ('update_time', models.CharField(default='2016-11-11 11:11', max_length=256)),
            ],
        ),
        migrations.CreateModel(
            name='Scan_result',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('match_hash', models.CharField(max_length=256)),
                ('pcap_name', models.CharField(default='', max_length=256)),
                ('start_time', models.CharField(max_length=256)),
                ('stop_time', models.CharField(max_length=256)),
                ('filter', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='sniff_Project',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pro_name', models.CharField(max_length=64, unique=True)),
                ('filter', models.CharField(max_length=256)),
                ('pcap_name', models.CharField(max_length=128)),
                ('netcard', models.CharField(max_length=128)),
                ('pkt_counts', models.IntegerField(null=True)),
                ('pcap_size', models.CharField(max_length=32)),
                ('stat', models.IntegerField(default=0)),
            ],
        ),
    ]
