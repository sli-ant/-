# coding:utf-8

import os
import sys
import re
import operator

def A_choiceselect(logfile,log):
    listfile = os.listdir(logfile)
    action = ['1.Ip List','2.Sql Injection List','3.Filter specific IP','4.Address List','5.XSS List','6.Scanner List','7.File Include List','8.All Type List','0.Exit']
    while True:
        print 'Choices:'
        for actionnum in action:
            print actionnum
        selectaction = raw_input('please select:')
        if selectaction == '1':
            iplistresultname = raw_input('Please enter a file name as the result:')
            if iplistresultname == '':
                iplistresultname = 'Ip_List.txt'
                print 'You didn\'t enter any information.So the result will save in Ip List.txt'
            print 'Please don\'t interrupt.'
            B_iplist(logfile,log,iplistresultname,listfile)     #ip统计
            print 'Done.\n'
        elif selectaction == '2':
            sqlinjectlistresultname = raw_input('Please enter a file name as the result:')
            if sqlinjectlistresultname == '':
                sqlinjectlistresultname = 'Sql_Injection_List.txt'
                print 'You didn\'t enter any information.So the result will save in Sql_Injection_List.txt'
            print 'Please don\'t interrupt.'
            B_SQLlist(logfile,sqlinjectlistresultname,listfile)     #sql注入统计
            print 'Done.\n'
        elif selectaction == '3':
            ipactionprintoutresultname = raw_input('Please enter a file name as the result:')
            if ipactionprintoutresultname == '':
                ipactionprintoutresultname = 'Filter_specific_IP.txt'
                print 'You didn\'t enter any information.So the result will save in Filter_specific_IP.txt'
            ipaddress = raw_input('Please enter an ipaddress as the printout:')
            print 'Please don\'t interrupt.'
            B_ipactionprintout(logfile,ipactionprintoutresultname,listfile,ipaddress)     #特定ip筛选
            print 'Done.\n'
        elif selectaction == '4':
            addresslistresultname = raw_input('Please enter a file name as the result:')
            if addresslistresultname == '':
                addresslistresultname = 'Address_List.txt'
                print 'You didn\'t enter any information.So the result will save in Address_List.txt'
            print 'Please don\'t interrupt.'
            B_Addresslist(logfile,log,addresslistresultname,listfile)     #address统计
            print 'Done.\n'
        elif selectaction == '5':
            xsslistresultname = raw_input('Please enter a file name as the result:')
            if xsslistresultname == '':
                xsslistresultname = 'XSS_List.txt'
                print 'You didn\'t enter any information.So the result will save in XSS_List.txt'
            print 'Please don\'t interrupt.'
            B_XSSlist(logfile,xsslistresultname,listfile)     #xss统计
            print 'Done.\n'
        elif selectaction == '6':
            scannerlistresultname = raw_input('Please enter a file name as the result:')
            if scannerlistresultname == '':
                scannerlistresultname = 'Scanner_List.txt'
                print 'You didn\'t enter any information.So the result will save in Scanner_List.txt'
            print 'Please don\'t interrupt.'
            B_Scannerlist(logfile,scannerlistresultname,listfile)     #scanner统计
            print 'Done.\n'
        elif selectaction == '7':
            fileincludelistresultname = raw_input('Please enter a file name as the result:')
            if fileincludelistresultname == '':
                fileincludelistresultname = 'File_Include List.txt'
                print 'You didn\'t enter any information.So the result will save in File_Include_List.txt'
            print 'Please don\'t interrupt.'
            B_Fileincludelist(logfile,fileincludelistresultname,listfile)     #文件包含统计
            print 'Done.\n'
        elif selectaction == '8':
            iplistresultname = 'Ip_List.txt'
            sqlinjectlistresultname = 'Sql_Injection_List.txt'
            addresslistresultname = 'Address_List.txt'
            xsslistresultname = 'XSS_List.txt'
            scannerlistresultname = 'Scanner_List.txt'
            fileincludelistresultname = 'File_Include_List.txt'
            print 'Please don\'t interrupt.'
            B_iplist(logfile,log,iplistresultname,listfile)
            B_SQLlist(logfile,sqlinjectlistresultname,listfile)
            B_Addresslist(logfile,log,addresslistresultname,listfile)
            B_XSSlist(logfile,xsslistresultname,listfile)
            B_Scannerlist(logfile,scannerlistresultname,listfile)
            B_Fileincludelist(logfile,fileincludelistresultname,listfile)
            #多类型筛选和统计
            print 'Done.\n'
        elif selectaction == '0':
            break
        else:
            print 'The input is invalid' 

def B_iplist(logfile,log,iplistresultname,listfile):
    #以下为抽取字段中的ip信息
    c = open(log,'w+')
    fullanswer = ''
    for logfilename in range(0,len(listfile)):
        with open(logfile + listfile[logfilename],'r') as file_to_read:
            while True:
                lines = file_to_read.readline()
                comp = re.compile(ur'\S+\s+\S+\s+\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s(\S+)\s\S+\s\S+\s\S+\s\S+\s\S+\s')
                answer = comp.findall(lines)
                for k in range(0,len(answer)):
                    fullanswer = str(answer[k]).replace('\'','').replace(',','.').replace('(','').replace(')','').replace(' ','')
                    #print fullanswer,k
                if not lines:
                    break
                    pass
                if fullanswer <> '' and fullanswer <> 'cs-username':
                    c.write(fullanswer+'\n')
    c.close()
    C_count(log,iplistresultname)

def B_SQLlist(logfile,sqlinjectlistresultname,listfile):
    #以下为筛选SQL注入语句
    c = open(sqlinjectlistresultname,'w+')
    fullanswer = ''
    for logfilename in range(0,len(listfile)):
        with open(logfile + listfile[logfilename],'r') as file_to_read:
            while True:
                lines = file_to_read.readline()
                comp = "%20select%20|%20and%201=1|%20and%201=2|%20exec|%27exec| information_schema.tables|%20information_schema.tables|%20where%20|%20union%20|%20SELECT%20|%2ctable_name%20|cmdshell|%20table_schema"  #自行修改匹配规则
                answer = re.findall(comp,lines)
                if len(answer) > 0:
                    fullanswer = answer[0]
                if not lines:
                    break
                    pass
                if fullanswer <> '' and fullanswer <> 'cs-username':
                    c.write(lines)
                fullanswer = ''
    c.close()

def B_ipactionprintout(logfile,ipactionprintoutresultname,listfile,ipaddress):
    #以下为筛选特定的ip信息
    c = open(ipactionprintoutresultname,'w+')
    fullanswer = ''
    list = os.listdir(logfile)
    for logfilename in range(0,len(list)):
        with open(logfile + listfile[logfilename],'r') as file_to_read:
            while True:
                lines = file_to_read.readline()
                comp = re.compile(ur'\S+\s+\S+\s+\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s(\S+)\s\S+\s\S+\s\S+\s\S+\s\S+\s') 
                answer = comp.findall(lines)
                if not lines:
                    break
                    pass
                if len(answer) > 0:
                    if answer[0] == ipaddress:
                        c.write(lines)
    c.close()

def B_Addresslist(logfile,log,addresslistresultname,listfile):
    #以下为访问路径筛选
    c = open(log,'w+')
    fullanswer = ''
    for logfilename in range(0,len(listfile)):
        with open(logfile + listfile[logfilename],'r') as file_to_read:
            while True:
                lines = file_to_read.readline()
                comp = re.compile(ur'\S+\s+\S+\s+\S+\s\S+\s(\S+)\s\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s')
                answer = comp.findall(lines)
                for k in range(0,len(answer)):
                    fullanswer = str(answer[k]).replace('\'','').replace(',','.').replace('(','').replace(')','').replace(' ','')
                    #print fullanswer,k
                if not lines:
                    break
                    pass
                if fullanswer <> '' and fullanswer <> 'cs-username':
                    c.write(fullanswer+'\n')
    C_count(log,addresslistresultname)

def B_XSSlist(logfile,xsslistresultname,listfile):
    #以下为XSS筛选
    c = open(xsslistresultname,'w+')
    fullanswer = ''
    for logfilename in range(0,len(listfile)):
        with open(logfile + listfile[logfilename],'r') as file_to_read:
            while True:
                lines = file_to_read.readline()
                comp = "%3C|%3c|%3E|%3e|%253c|%253C|%253E|%253e|alert|confirm|prompt|document.cookie|%3cscript|javascript|window.open|document.write|xss"   #自行修改匹配规则
                answer = re.findall(comp,lines)
                if len(answer) > 0:
                    fullanswer = answer[0]
                if not lines:
                    break
                    pass
                if fullanswer <> '' and fullanswer <> 'cs-username':
                    c.write(lines)
                fullanswer = ''
    c.close()

def B_Scannerlist(logfile,scannerlistresultname,listfile):
    #以下为扫描器扫描筛选
    c = open(scannerlistresultname,'w+')
    fullanswer = ''
    for logfilename in range(0,len(listfile)):
        with open(logfile + listfile[logfilename],'r') as file_to_read:
            while True:
                lines = file_to_read.readline()
                comp = "sqlmap|acunetix|Netsparker|nmap|wvs|Appscan|Webinspect|Rsas|Nessus|WebReaver"   #自行修改匹配规则
                answer = re.findall(comp,lines)
                if len(answer) > 0:
                    fullanswer = answer[0]
                if not lines:
                    break
                    pass
                if fullanswer <> '' and fullanswer <> 'cs-username':
                    c.write(lines)
                fullanswer = ''
    c.close()

def B_Fileincludelist(logfile,fileincludelistresultname,listfile):
    #以下文件包含筛选
    c = open(fileincludelistresultname,'w+')
    fullanswer = ''
    list = os.listdir(logfile)
    for logfilename in range(0,len(listfile)):
        with open(logfile + listfile[logfilename],'r') as file_to_read:
            while True:
                lines = file_to_read.readline()
                comp = "/passwd|%00|/win.ini|/my.ini|/MetaBase.xml|/ServUDaemon.ini|/shadow"
                answer = re.findall(comp,lines)
                if len(answer) > 0:
                    fullanswer = answer[0]
                if not lines:
                    break
                    pass
                if fullanswer <> '' and fullanswer <> 'cs-username':
                    comp = re.compile(ur'\S+\s+\S+\s+\S+\s\S+\s(\S+)\s\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s\S+\s')
                    answer = comp.findall(lines)
                    for k in range(0,len(answer)):
                        fullanswer = str(answer[k]).replace('\'','').replace(',','.').replace('(','').replace(')','').replace(' ','')
                    c.write(fullanswer+'\n')
                fullanswer = ''
    c.close()
    
def C_count(log,listresultname):
    #以下为统计次数
    c = open(log,'r')
    m = open(listresultname,'w+')
    count_dict = {}
    for line in c.readlines():
        line = line.strip()
        count = count_dict.setdefault(line, 0)
        count += 1
        count_dict[line] = count
    sorted_count_dict = sorted(count_dict.iteritems(), key=operator.itemgetter(1), reverse=True)
    for item in sorted_count_dict:
        m.write(item[0]+'  '+str(item[1])+'\n')
 
if __name__ == '__main__':
    print 'For example: E:\\test\\'
    logfile = raw_input("please enter your log file dictionary:")   #输入日志目录
    log = 'listfile.txt'  #保存过程文件，用于处理中间的数据信息，可无视
    A_choiceselect(logfile,log)
    os.remove(log)
