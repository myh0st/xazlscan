#!/usr/bin/env python3

import re
import os
import sys
import json
import hashlib
import base64
import zipfile
import time
import random
import shutil
import subprocess
import ssl
import requests
import warnings
from gzip import GzipFile
from lib.util import judgeRuleTime



try:
    from StringIO import StringIO
    readBytesCustom = StringIO
except ImportError:
    from io import BytesIO
    readBytesCustom = BytesIO

try:
    from urllib.request import Request, urlopen
except ImportError:
    from urllib2 import Request, urlopen


warnings.filterwarnings("ignore")


#检查单条规则
def check_rule(rule, site_info):
    title = site_info[0]
    header = site_info[1]
    server = site_info[2]
    body = site_info[3]

    #print(rule, title, header)
    for r in rule:
        try:
            func = r['match']
        except:
            print(r)
        content = r['content'].lower()
        #print(func, content, header)
        #sys.exit()
        if  func == 'header_contains':
            if content not in header:
                return False
        elif func == 'body_contains':
             if content not in body:
                return False
        elif func == 'server_contains':
             if content not in server:
                return False
        elif func == 'title_contains':
             if content not in title:
                return False
        else:
            return False
    return True

#获取网站信息, 输出规则检查所需内容
def get_headers():
    """
    生成伪造请求头
    """
    user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
            'Gecko/20100101 Firefox/68.0',
            'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0']
    ua = random.choice(user_agents)
    headers = {
        'Accept': 'text/html,application/xhtml+xml,'
                  'application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'DNT': '1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': ua,
    }
    return headers

def get_response(url, response, ignore=False):
    if ignore:
        html = ""
        size = response.headers.get("content-length", default=1000)
    else:
        response.encoding = response.apparent_encoding if response.encoding == 'ISO-8859-1' else response.encoding
        response.encoding = "utf-8" if response.encoding is None else response.encoding
        html = response.content.decode(response.encoding,"ignore")
        size = len(response.text)
    return response.status_code, response.headers, html

def send_request(url):
    '''
    Send requests with Requests
    '''
    try:
        #proxies = { "http": "127.0.0.1:8080","https": "127.0.0.1:8080"}
        with requests.get(url, timeout=10, headers=get_headers(), verify=False,
                          allow_redirects=True) as response:
            if int(response.headers.get("content-length", default=1000)) > 100000:
                code, rep_headers, body = get_response(url, response, True)
            else:
                code, rep_headers, body = get_response(url, response)
    except KeyboardInterrupt:
        print("用户强制程序，系统中止!")
        exit(0)
    except Exception as e:
        print(e)
        return "", 0, "", "", ""

    server = ""
    if "Server" in rep_headers:
        server = rep_headers["Server"]
    
    title = ""
    titles=re.findall(r"<\s*title\s*>\s*([^<]+)\s*<\s*\/title\s*>",body, re.I)
    if len(titles) != 0:
        title = titles[0]


    return title.lower(), code, server.lower(), str(rep_headers).lower(), body.lower()

#获取网站信息并识别指纹
def get_site_info(website, sytem_rules):
    title, status, server, header, body = send_request(website)
    site_info = [title, header, server, body]
    n = 0
    systemlist = []
    for sid in sytem_rules:
        flag = False
        for rule in sytem_rules[sid]["rules"]:
            if check_rule(rule, site_info):
                flag = True
                break
        if flag == True:
            systemlist.append(sid)
            break
    return systemlist

#初始化规则库
def initSysRules(email, token):
    url = "https://www.xazlsec.com/api/get_sysrules/?token={}&email={}".format(token, email)
    rulepath = "config/sysrule.json"
    if not os.path.exists(rulepath) or not judgeRuleTime(rulepath):
        sysinfo = requests.get(url, timeout=20).json()
        open(rulepath, "w", encoding="utf-8").write(json.dumps(sysinfo))
    return sysinfo
    
#下载POC到本地
def downloadPoc(savefile, pocuuid, email, token):
    url = "https://www.xazlsec.com/api/download_poc/?token={}&id={}&email={}".format(token, pocuuid, email)

    pocdata = requests.get(url)

    try:
        info = pocdata.json()
        return info["msg"]
    except:
        pass

    open(savefile, "wb").write(pocdata.content)

#搜索POC信息
def searchPoc(sid, token, email):
    url = "https://www.xazlsec.com/api/search_poc/?token={}&sid={}&email={}".format(token, sid, email)
    jsondata = requests.get(url).json()
    return jsondata

#购买POC
def buyPoc(sid, token, email):
    url = "https://www.xazlsec.com/api/buy_poc/?token={}&sid={}&email={}".format(token, sid, email)
    jsondata = requests.get(url).json()
    return jsondata

#检查Token是否有效
def checkToken(token, email):
    url = "https://www.xazlsec.com/api/check_token/?token={}&email={}".format(token, email)
    jsondata = requests.get(url).json()
    if jsondata["status"] == "false":
        return False

    return jsondata["uid"]
