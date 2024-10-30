#!/usr/bin/env python3

import os
import sys
import json
import time
import uuid
import subprocess
from configparser import ConfigParser

respath = "res/"
vulnpath = "vulns/"

#获取配置中的token和email
def getTokenOrEmail():
    # 创建解析器实例
    config = ConfigParser()
    # 读取配置文件
    config.read('config/config.ini')
    
    # 获取信息
    email = config.get('login', 'email')
    token = config.get('login', 'token')
    return email, token

#判断规则库的有效期
def judgeRuleTime(rulepath):
    if not os.path.exists(rulepath):
        return False
    sysinfo = json.loads(open(rulepath, encoding="utf-8").read())
    downtime = sysinfo["timestamp"]
    nowtime = time.time()
    if int(nowtime) - int(downtime) > 24 * 60 * 60:
        return False
    return True

#执行系统命令
def execCmd(cmdline):
    rsp = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = rsp.communicate()
    return output, error

#读取文件内容
def readFile(filepath):
    return open(filepath, encoding="utf-8").read()

#检查临时目录是否存在，并新建目录
def getTmpUuid():
    uinfo = str(uuid.uuid4())

    if not os.path.exists(respath):
        os.mkdir(respath)
    if not os.path.exists(respath+uinfo):
        os.mkdir(respath+uinfo)

    if not os.path.exists(vulnpath):
        os.mkdir(vulnpath)
    if not os.path.exists(vulnpath+uinfo):
        os.mkdir(vulnpath+uinfo)

    return uinfo

#保存文件内容
def saveFile(savefile, info):
    obj = open(savefile, "a+", encoding="utf-8")
    obj.writelines(info+"\n")
    obj.close()

#获取网页跟目录
def getRootSite(url):
    return "/".join(url.split("/")[:3])
