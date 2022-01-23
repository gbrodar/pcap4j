#!/usr/bin/python

import os
import sys
import re
import json
import requests
import brothon
import ipwhois
import time

from brothon import bro_log_reader
from pprint import pprint
from neo4j.v1 import GraphDatabase


PCAP_FILE = sys.argv[1]
WORK_DIR = "/tmp"
NEO4JUSER = ''
NEO4JPASSWORD = ''

def bro_prep(PCAP_FILE):
	bro_command = "bro -r ./" + PCAP_FILE + " -C frameworks/files/extract-all-files frameworks/files/hash-all-files.bro protocols/http/http-headers-logs.bro"
	print bro_command
	os.system(bro_command)
	os.system("mv *.log /tmp")
	os.system("mkdir -p /tmp/extracted_files")
	os.system("mv ./extract_files/* /tmp/extracted_files")

def neo4j_connector():
	driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=(NEO4JUSER, NEO4JPASSWORD))
	driver.close()

def neo4j_add_hosts(nodes_list):
	driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=(NEO4JUSER, NEO4JPASSWORD))
	session = driver.session()
	if nodes_list["src_ip"] != "":
		result = session.run("MERGE (Src:local_host {ip_address:$src_ip, capture_date:$capture_date, ek_type:$ek_type})", src_ip=nodes_list["src_ip"], capture_date=capture_date, ek_type=ek_type)
		for element in result:
			print element
		result = session.run("MERGE (Dst:host {ip_address:$dst_ip})", dst_ip=nodes_list["dst_ip"])
		for element in result:
			print element
		result = session.run("MATCH (Src:local_host {ip_address:$src_ip, capture_date:$capture_date, ek_type:$ek_type}) MATCH (Dst:host {ip_address:$dst_ip}) MERGE (Src)-[:GET]->(Dst)", src_ip=nodes_list["src_ip"], capture_date=capture_date, ek_type=ek_type, dst_ip=nodes_list["dst_ip"])
		for element in result:
			print element
		result = session.run("MATCH (Host:host {ip_address:$ip_address}) MERGE (Domain:domain {domain:$host}) MERGE (Host)-[:HOSTS]->(Domain)", ip_address=nodes_list["dst_ip"], host=nodes_list["host"])
		for element in result:
			print element
	if nodes_list["referrer"] != "":
		result = session.run("MATCH (Src:domain {domain:$referrer}) MATCH (Dst:domain {domain:$host}) MERGE (Src)-[:REFER]->(Dst)", referrer=nodes_list["referrer"], host=nodes_list["host"])
		for element in result:
			print element
	if nodes_list["redirect"] != "":
		result = session.run("MATCH (Src:domain {domain:$host}) MATCH (Dst:domain {domain:$redirect}) MERGE (Src)-[:REDIRECT]->(Dst)", host=nodes_list["host"], redirect=nodes_list["redirect"])
		for element in result:
			print element

def neo4j_add_files(file_list):
	driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "Neo4j666!"))
	session = driver.session()
	result = session.run("MERGE (File:file {hash:$sha1, filename:$filename, type:$mime_type})", sha1=file_list["sha1"], filename=file_list["filename"], mime_type=file_list["mime_type"])
	for element in result:
		print element
	result = session.run("MATCH (Domain:domain)--(Host:host {ip_address:$ip_address}) MATCH (File:file {hash:$sha1}) MERGE (Domain)-[:DROPS]->(File)", ip_address=file_list["src"], sha1=file_list["sha1"])
	for element in result:
		print element

def log_reader():
	nodes = []
	reader = bro_log_reader.BroLogReader('/tmp/http.log')
	for row in reader.readrows():
		if row['status_code'] == 200:
			host = row['host']
			referrer = row['referrer']
			if referrer != '-':
				referrer_host = re.search('://(.*?)\/', referrer)
				if referrer_host is not None:
					referrer_host = referrer_host.group(1)
			else:
				referrer_host = ""
			src_ip = row['id.orig_h']
			dst_ip = row['id.resp_h']
			nodes = {"host": host, "referrer": referrer_host, "src_ip": src_ip, "dst_ip": dst_ip, "redirect": ""}
			neo4j_add_hosts(nodes)


		if row['status_code'] in [301, 302]:
			if 'LOCATION' in row['server_header_names']:
				orig_host = row['host']
				server_header_names = row['server_header_names'].split(",")
				location_header_position = server_header_names.index("LOCATION")
				server_header_values = row['server_header_values'].split(",")
				redirect_url = server_header_values[location_header_position]
				redirect_host = re.search('://(.*?)\/', redirect_url)
				if redirect_host is not None:
					redirect_host = redirect_host.group(1)
					nodes = {"host": orig_host, "referrer": '', "src_ip": '', "dst_ip": '' , "redirect": redirect_host}
					neo4j_add_hosts(nodes)

def file_log_reader():
	file_log_reader = bro_log_reader.BroLogReader('/tmp/files.log')
	for row in file_log_reader.readrows():
		if row['mime_type'] in ["application/x-7z-compressed",\
					 "application/x-shockwave-flash",\
					 "application/pdf",\
					 "application/vnd.android.package-archive",\
					 "application/x-apple-diskimage",\
					 "application/vnd.apple.installer+xml",\
					 "application/octet-stream",\
					 "application/java-archive",\
					 "application/x-java-jnlp-file",\
					 "application/javascript", \
					 "application/x-msdownload", \
					 "application/x-ms-application", \
					 "application/vnd.ms-excel.sheet.macroenabled.12",\
				 	 "application/vnd.ms-htmlhelp", \
					 "application/vnd.ms-powerpoint", \
					 "application/vnd.ms-powerpoint.presentation.macroenabled.12",\
					 "application/x-mspublisher",\
					 "application/msword",\
					 "application/zip",\
					 "application/x-dosexec" ]:

			file_list = {'mime_type': row['mime_type'], 'filename': row['filename'], 'sha1': row['sha1'], 'src': row['tx_hosts']}
			neo4j_add_files(file_list)


if __name__ == "__main__":
	capture_date = PCAP_FILE[0:10].replace("-","")
	ek = re.search('-(\w*)-EK', PCAP_FILE)
	ek_type = ek.group(1)
	print capture_date
	print ek_type
	bro_prep(PCAP_FILE)
	log_reader()
	file_log_reader()

