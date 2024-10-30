#!/usr/bin/env python3

import os
import sys
import click
import threading
import queue
from lib.req import *
from lib.util import *

respath = "res/"
vulnpath = "vulns/"
pocpath = "pocdb/"
if sys.platform == 'win32':
    nucleipath = "bin\\nuclei.exe"
else:
    nucleipath = "bin/nuclei"
rulepath = "config/sysrule.json"
inputQueue = queue.Queue()
num = 0
length = 0
sysrules = {}


#基于SID获取相关信息，根据用户选择同步 POC 到本地
def getPocToLocal(sid, token, email):
    pocinfo = searchPoc(sid, token, email)
    if pocinfo["status"] == "false":
        print("[-]查询POC信息失败，错误提示：", pocinfo["msg"])
        return False

    print("[+]系统信息：", pocinfo["sysinfo"])
    if pocinfo["pnum"] == 0:
        print("[+]该系统所涉及的POC为0，无法进行后续操作！")
        return False

    newpoc = pocinfo["pnum"]-pocinfo["bnum"]
    if newpoc != 0:
        print("[+]积分信息，剩余积分：", pocinfo["score"], "本次扫描需要消耗积分：", newpoc * 5)
        select = input("[+]是否确定要消耗积分并执行漏洞探测？（0 否）")
        if select == "0":
            return False

    buyinfo = buyPoc(sid, token, email)
    if buyinfo["status"] == "false":
        print("[-]POC购买失败，错误提示：", buyinfo["msg"])
        return False
    if newpoc != 0:
        print("[+]购买成功，剩余积分：", buyinfo["score"])
    poclist = buyinfo["poclist"]

    if not os.path.exists(pocpath):
        os.mkdir(pocpath)

    savepath = pocpath + str(sid)
    if not os.path.exists(savepath):
        os.mkdir(savepath)

    #同步下载POC到本地
    for poc in poclist:
        puuid = poc[0]
        pname = poc[1]
        savefile = savepath + "/" + pname + ".yaml"
        if not os.path.exists(savefile):
            print("[+]正在下载POC：", savefile)
            downloadPoc(savefile, puuid, email, token)
    print("[+]POC已全部下载同步，即将启动 nuclei 进行漏洞探测")
    return True

#检测基础环境
def checkBase(email, token):
    #首先检查用户token是否有效
    if not checkToken(token, email):
        print("[-]Token 无效，请前往 https://www.xazlsec.com 的个人资料中查看有效和 token 并更新配置文件")
        return False
    #检查 nuclei 是否安装
    if not os.path.exists(nucleipath):
        print("[-]nuclei 未下载至 bin 目录，无法使用漏洞探测，请下载 nuclei 到指定目录")
        return False

    return True

#针对单个网站进行指纹识别以及漏洞探测
def scanSingleSite(target):
    email, token = getTokenOrEmail()

    if not checkBase(email, token):
        sys.exit()

    #第一步，初始化指纹库，并读取指纹规则
    if not judgeRuleTime(rulepath):
        sysRules = initSysRules(email, token)
    else:
        sysRules = json.loads(open(rulepath, encoding="utf-8").read())

    #第二步，获取网页信息并识别指纹
    rootsite = getRootSite(target)
    sysList = get_site_info(rootsite, sysRules["system_rules"])
    uinfo = getTmpUuid()   

    #判断是否识别为蜜罐，指纹识别结果超过阈值
    if len(sysList) >= 6:
        print("[-]该网站识别结果超过 6 个，疑似蜜罐，漏洞探测程序退出！")
        sys.exit()

    #第三步，根据获取到的系统列表，判断用户是否有足够的积分购买POC
    for sid in sysList:
        if not getPocToLocal(sid, token, email):
            continue

        vulnfile = vulnpath + uinfo + "/" + str(sid) + ".txt"
        if sys.platform == 'win32':
            cmd = nucleipath + " -duc -t " + pocpath + str(sid) + "/ -u " + rootsite + " -o " + vulnfile
        else:
            cmd = "./" + nucleipath + " -duc -t " + pocpath + str(sid) + "/ -u " + rootsite + " -o " + vulnfile
        #print(cmd)
        execCmd(cmd)

    #读取漏洞文件，获取漏洞结果
    print("[+]漏洞检测结果如下：")
    for filename in os.listdir(vulnpath + uinfo):
        print(readFile(vulnpath + uinfo + "/" + filename))
          
           
#针对多个网站进行指纹识别及漏洞探测，非多线程版
def auto_get():
    global sysrules
    global length
    global num
    while True:
        num = num + 1
        rootsite = inputQueue.get()
        syslist = get_site_info(rootsite, sysrules)
        
        #判断是否识别为蜜罐，指纹识别结果超过阈值
        if len(syslist) >= 6:
            continue
        
        #print(sysrules)
        for sid in syslist:
            saveFile(respath+uinfo+"/"+str(sid)+".txt", rootsite)
        if num % 100 == 0:
            print("[+]正在指纹识别网站：", rootsite, "网站总数：", length, "当前进度：", num)
            

def scanSiteFile(tfile, thread=30):
    global length
    global sysrules
    global uinfo
    email, token = getTokenOrEmail()

    if not checkBase(email, token):
        sys.exit()

    if not os.path.exists(tfile):
        print("[-]指定文件不存在，请确保指定的文件路径正确！")
        sys.exit()

    #第一步，初始化指纹库，并读取指纹规则
    if not judgeRuleTime(rulepath):
        sysRules = initSysRules(email, token)
    else:
        sysRules = json.loads(open(rulepath, encoding="utf-8").read())

    #第二步，获取网站信息并识别指纹，将结果保存在临时目录下
    uinfo = getTmpUuid()
    #启用多线程，创建线程池
    for x in range(int(thread)):
        t = threading.Thread(target=auto_get)
        t.setDaemon(True)
        t.start()

    length = len(list(open(tfile, encoding="utf-8")))
    sysrules = sysRules["system_rules"]
    sitelist = []
    for site in open(tfile, encoding="utf-8"):
        rootsite = getRootSite(site.strip())
        if rootsite not in sitelist:
            inputQueue.put(rootsite)
        
        while True:
            if inputQueue.qsize() <= 1000:
                break
            else:
                time.sleep(5)

    while True:
        time.sleep(5)
        if inputQueue.qsize() <= 1:
            break
    #多线程部分结束
        
    #第三步，根据获取到的所有系统类型，一一计算需要消耗的积分数
    for sfile in os.listdir(respath+uinfo):
        sid = sfile.split(".")[0]
        if not getPocToLocal(sid, token, email):
            continue

        vulnfile = vulnpath + uinfo + "/" + str(sid) + ".txt"
        if sys.platform == 'win32':
            cmd = nucleipath + " -duc -t " + pocpath + str(sid) + "/ -l " + respath + uinfo + "/" + sfile + " -o " + vulnfile
        else:
            cmd = "./" + nucleipath + " -duc -t " + pocpath + str(sid) + "/ -l " + respath + uinfo + "/" + sfile + " -o " + vulnfile
        execCmd(cmd)

    #最后，将所有漏洞检测的结果进行展示
    #读取漏洞文件，获取漏洞结果
    print("[+]漏洞检测结果如下：")
    for filename in os.listdir(vulnpath + uinfo):
        print(readFile(vulnpath + uinfo + "/" + filename))

@click.command()
@click.option("-u", "--target", help="指定需要检测的目标地址")
@click.option("-f", "--tfile", help="指定需要检测的目标文件路径")
@click.option("-t", "--thread", help="指定指纹识别时使用的线程数默认30")

def main(target, tfile, thread):
    if target:
        scanSingleSite(target)

    if tfile:
        if thread:
            scanSiteFile(tfile, thread)
        else:
            scanSiteFile(tfile)
        

if __name__=="__main__":
    main()
