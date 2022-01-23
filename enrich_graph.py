#!/usr/bin/python

import os
import sys
import re
import json
import requests
import time

from pprint import pprint
from neo4j.v1 import GraphDatabase
VT_API_KEY = "YOUR-VT-API-KEY-HERE"
NEO4JUSER = ''
NEO4JPASSWORD = ''

def neo4j_connector():
        driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=(NEO4JUSER, NEO4JPASSOWRD))
        driver.close()

def collect_nodes():
	driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=(NEO4JUSER, NEO4JPASSWORD))
        session = driver.session()

	for type in mime_type:
		result = session.run('MATCH(f:file {type:$type}) RETURN f', type=type)
		for record in result:
			if record["f"]["hash"] != "-":
				sha1 = record["f"]["hash"]

			        params = {'apikey': VT_API_KEY, 'resource': sha1}
      				headers = {"Accept-Encoding": "gzip, deflate"}
			        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
			        json_response = response.json()
			        pprint (json_response)
				time.sleep(15)

				if json_response['response_code'] != 0:
					print json_response["scans"]

					for scan in json_response['scans']:
						scan_result = json_response['scans'][scan]['result']
						if scan_result is not None:
							print "Scan done! for " + sha1
							merge_result = session.run(" MATCH (File:file {hash:$sha1}) MERGE (Scan:scan {av:$av, result:$result}) MERGE (File)-[:MATCHES]->(Scan)", av=scan, result=scan_result, sha1=sha1)
							for element in merge_result:
								print element


def collect_drop_sites():
	driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", "Neo4j666!"))
	session = driver.session()

	result = session.run('MATCH (Host:host)-[:HOSTS]->(Domain:domain)-[:DROPS]->(File:file)-[:MATCHES]->(Scan:scan) RETURN DISTINCT Host')
	for record in result:
		host_ip = record['Host']['ip_address']
		ip_address = record['Host']['ip_address']
		params = {'ip': ip_address, 'apikey': VT_API_KEY}
		headers = {"Accept-Encoding": "gzip, deflate"}
		response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=params, headers=headers)
		json_response = response.json()
		if 'asn' in json_response:
			as_number = json_response['asn']
		else:
			as_number = ''
		if 'as_owner' in json_response:
			as_owner = json_response['as_owner']
		else:
			as_owner = ''
		if 'country' in json_response:
			as_country = json_response['country']
		else:
			as_country = ''
		merge_result = session.run('MATCH (Host:host {ip_address:$host_ip}) MERGE (ASN:asn {as_owner:$as_owner, as_number:$as_number, as_country:$as_country}) MERGE (Host)-[:BELONGS_TO]->(ASN)', as_number=as_number, as_owner=as_owner, as_country=as_country, host_ip=host_ip)
		for element in merge_result:
			print element

		if 'detected_urls' in json_response:
			for url in json_response['detected_urls']:
				detected_host = re.search('://(.*?)\/', url['url'])
				if detected_host is not None:
					detected_host = detected_host.group(1)
					merge_result = session.run('MATCH (Host:host {ip_address:$host_ip}) MERGE (Bad_Host:bad_host {domain:$detected_host}) MERGE (Host)-[:ALSO_HOSTS]->(Bad_Host)', host_ip=host_ip, detected_host=detected_host)
					for element in merge_result:
						print merge_result

		if 'detected_downloaded_samples' in json_response:
			for sample in json_response['detected_downloaded_samples']:
				detected_sample = sample['sha256']
				if detected_sample is not None:
					merge_result = session.run('MATCH (Host:host {ip_address:$host_ip}) MERGE (Bad_Sample:bad_sample {hash:$hash}) MERGE (Host)-[:ALSO_DROPS]->(Bad_Sample)', host_ip=host_ip, hash=detected_sample)
					for element in merge_result:
						print merge_result



if __name__ == "__main__":

	mime_type = ["application/x-7z-compressed",\
                                        "application/x-shockwave-flash",\
                                         "application/pdf",\
                                         "application/octet-stream",\
                                         "application/java-archive",\
                                         "application/x-java-jnlp-file",\
                                         "application/javascript", \
                                         "application/x-msdownload", \
                                         "application/x-ms-application", \
                                         "application/msword",\
                                         "application/zip",\
                                         "application/x-dosexec"]
	collect_nodes()
	collect_drop_sites()
