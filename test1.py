# coding=utf-8
from tkinter import ttk, filedialog, Tk, StringVar, Menu, Scrollbar, Toplevel, messagebox, IntVar
from tkinter.constants import END
from lxml import etree
import pyperclip
import requests
import base64
import json
import random
import traceback
from config import rules_path
from github import Github
import ctypes
import threading
from ttkthemes import *
import queue
import os
import re
from bypassWAF import bypassWAF
from config import USERAGENT
from config.rules import ruleDatas
from FUNCTION import ParseRecord
from FUNCTION import fidcount
from FUNCTION import AScreenshot
from FUNCTION import DNSSub
from FUNCTION import SSLQ
from FUNCTION import googles
from FUNCTION import EnterpriseArchitecture
from FUNCTION import Tools
from FUNCTION import DomainContras
from FUNCTION import Certificatecheck
from FUNCTION import iconCheck
from FUNCTION import JSCheck
from FUNCTION import SUBDOMAIN
from FUNCTION import ipi
from FUNCTION import edui
from FUNCTION import zoomeyen
import time
import csv
import webbrowser
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()


def aswync(f):
    def wrapper(*args, **kwargs):
        thr = threading.Thread(target=f, args=args, kwargs=kwargs)
        thr.start()

    return wrapper


def reads():
    with open("FUNCTION/google_domain.txt", "r+", encoding="utf-8") as f:
        google_list = []
        for i in f.readlines():
            line = i.strip()
            google_list.append(line)
    return google_list


@aswync
def google_hacker(search, page):
    x = tree.get_children()
    for item in x:
        tree.delete(item)
    lists = googles.search(search, num_results=page, proxy=proxies)
    for i in lists:
        print(i)
        update_result(i, "", "", "", "", "", "")
        with open(r"out/google_hack.txt", "a+") as f:
            f.write(i + '\n')
            f.write("________________________________________________________________________" + "\n")


def ea():
    new_num()
    tree.heading('1', text="序号")
    tree.heading('2', text='URL')
    tree.column('1', width=150, anchor='center')
    tree.column('2', width=1200, anchor='center')
    search = e1.get()
    page = int(e2.get())
    google_hacker(search, page)


def ea2():
    new_num()
    tree.heading('1', text="序号")
    tree.heading('2', text='URL')
    tree.column('1', width=150, anchor='center')
    tree.column('2', width=1000, anchor='center')
    google_hacker(search, page)


def google_help2():
    load_ui()
    global page
    global search
    page = 100
    search = Entry_1.get()
    global proxies
    ds = "https://{}".format(domainss2)
    proxies = {'http': "http://{}".format(domainss2), 'https': ds}
    ea2()


def google_help():
    global proxies
    ds = "https://{}".format(domainss2)
    proxies = {'http': "http://{}".format(domainss2), 'https': ds}
    print(proxies)
    global e1
    global e2
    global search
    global page
    top = Toplevel()
    top.title('google hack')
    top.wm_attributes("-topmost", 1)
    top.geometry("400x150+550+250")
    top.resizable(width=False, height=False)
    L1 = ttk.Label(top, text="关键字", font=("宋体", 9))
    L1.place(relx=0.020, rely=0.030, relwidth=0.30, relheight=0.30)
    e1 = ttk.Entry(top)
    e1.place(relx=0.2, rely=0.10, relwidth=0.600, relheight=0.2)
    L2 = ttk.Label(top, text="数量", font=("宋体", 9))
    L2.place(relx=0.020, rely=0.4, relwidth=0.3, relheight=0.20)
    e2 = ttk.Entry(top)
    e2.place(relx=0.2, rely=0.40, relwidth=0.600, relheight=0.2)
    b = ttk.Button(top, text="查询", command=ea)
    b.place(relx=0.820, rely=0.090, relwidth=0.140, relheight=0.20)
    L2 = ttk.Label(top, text="提醒:多个关键字可以用+连接,结果自动保存在out目录下", font=("宋体", 9))
    L2.place(relx=0.020, rely=0.6, relwidth=0.9, relheight=0.20)


def weixin_help():
    global e1
    global e2
    global search
    global page
    top = Toplevel()
    top.title('weixin hack')
    top.wm_attributes("-topmost", 1)
    top.geometry("400x150+550+250")
    top.resizable(width=False, height=False)
    L1 = ttk.Label(top, text="关键字", font=("宋体", 9))
    L1.place(relx=0.020, rely=0.030, relwidth=0.30, relheight=0.30)
    e1 = ttk.Entry(top)
    e1.place(relx=0.2, rely=0.10, relwidth=0.600, relheight=0.2)
    L2 = ttk.Label(top, text="页数", font=("宋体", 9))
    L2.place(relx=0.020, rely=0.4, relwidth=0.3, relheight=0.20)
    e2 = ttk.Entry(top)
    e2.place(relx=0.2, rely=0.40, relwidth=0.600, relheight=0.2)
    b = ttk.Button(top, text="查询", command=ea4)
    b.place(relx=0.820, rely=0.090, relwidth=0.140, relheight=0.20)


def ea4():
    new_num()
    tree.heading('1', text="序号")
    tree.heading('2', text='URL')
    tree.heading('3', text='公众号')
    tree.heading('4', text='内容截取')
    tree.column('1', width=50, anchor='center')
    tree.column('2', width=100, anchor='center')
    tree.column('3', width=100, anchor='center')
    tree.column('4', width=1100, anchor='center')
    search = e1.get()
    page = int(e2.get())
    weixin_hacker(search, page)


def GenerateKeywords(hosts):
    key = ['jdbc:', 'password', 'username', 'database', 'smtp', 'vpn', 'pwd', 'passwd', 'connect', "密码"]
    keywords = []

    for h in hosts:
        if "@" in h:
            h = h.split("@")[0] + " smtp"

        for k in key:
            keywords.append(h + " " + k)

    return keywords


def _analysis_result(items, key):
    result_id = 0
    result_count = len(items)

    if not result_count:
        result("目标为空", key, "", "", "", "")
        return None

    while result_id < result_count:
        item = items[result_id]
        try:
            if all(list([kw in item.decoded_content.decode("utf8") for kw in key.split(" ")])):
                negative = "疑似"
            else:
                negative = "False"
            url = "https://www.github.com/" + \
                  item.repository.full_name + "/blob/master/" + item.path
            print(url)
            update_result(url, key, negative, "", "", "")

        except Exception as e:
            print(e)
        result_id += 1


@aswync
def _analysis_page(result, key):
    page_id = 0
    while page_id < 34:
        try:
            iteks = result.get_page(page_id)
            ana_result = _analysis_result(iteks, key)
            if not ana_result:
                print("[WARNING] 在第{}页退出".format(page_id))
                break
        except Exception as e:
            print(e)
    page_id += 1
    print("[INFO] 结束关键字: " + key + "\n\n")


def treeviewClick(event):
    global item_text
    menu.post(event.x_root, event.y_root)
    for item in tree.selection():
        item_text = tree.item(item, "values")
        return item_text


def gourl(event):
    for item in tree.selection():
        item_text = tree.item(item, "values")
        webbrowser.open(item_text[1])


def display_messagebox2():
    messagebox.showinfo(title='提示',
                        message='不能同时开启')


def copyIP():
    global item_text
    pyperclip.copy(item_text[2])


def copyFid():
    global item_text
    pyperclip.copy('fid="' + item_text[7] + '"')


def copyURL():
    global item_text
    pyperclip.copy(item_text[1])


def copybackup():
    global item_text
    pyperclip.copy(item_text[3])


def on_closing():
    os._exit(0)


def stop():
    global stop_run
    stop_run = True
    Label_4.config(text="正在终止线程...")


def new_num():
    global num
    num = 1


def fofa():
    if Checkbutton_2.get() == "开启标签过滤" and Checkbutton_1.get() == "开启敏感目录":
        display_messagebox2()
    else:
        fofa_tree()
        Label_4.config(text="正在获取数据...")
        global stop_run
        new_num()
        t = []
        stop_run = False
        x = tree.get_children()
        for item in x:
            tree.delete(item)
        q = queue.Queue()
        b = queue.Queue()
        if h11.get():
            if "&& (is_honeypot=false && is_fraud=false)" in Entry_11.get():
                query = Entry_11.get()
            else:
                query = "(" + Entry_11.get() + ") && (is_honeypot=false && is_fraud=false)"
                Entry_11.delete(0, END)
                Entry_11.insert('0', query)
        else:
            query = Entry_11.get()
        count = int(comboxlist2.get())
        daoru = False
        th = int(comboxlist1.get())
        fields = "host,title,ip,port,domain,server,fid"
        query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
        r = requests.get(
            url="https://fofa.so/api/v1/search/all?email={}&key={}&fields={}&qbase64={}&size={}".format(fofa_email,
                                                                                                        fofa_key,
                                                                                                        fields, query,
                                                                                                        count),
            proxies=proxies)
        data = json.loads(r.text.encode("GBK", 'ignore').decode('GBK'))
        if Checkbutton_2.get() == "开启标签过滤" or Checkbutton_1.get() == "开启敏感目录":
            for i in data['results']:
                if 'http' in i[0]:
                    pass
                else:
                    if ':443' in i[0]:
                        i[0] = 'https://' + i[0]
                    else:
                        i[0] = 'http://' + i[0]
                q.put(i)
            for i in range(th):
                thread = threading.Thread(target=spider, args=(q, b, Checkbutton_1.get(), daoru))
                t.append(thread)
            for i in range(th):
                t[i].start()

        else:
            for i in data['results']:
                if 'http' in i[0]:
                    host = i[0]
                else:
                    if ':443' in i[0]:
                        host = 'https://' + i[0]
                    else:
                        host = 'http://' + i[0]
                title = i[1].strip()
                ip = i[2]
                prot = i[3]
                domain = i[4]
                server = i[5]
                fid = i[6]
                result(host, title, ip, prot, domain, server, fid, '', '')
            Label_4.config(text="fofa任务已结束")
        if Checkbutton_1.get() == "开启敏感目录":
            Label_4.config(text="目录扫描结束")


def spider(q, b, brute, daoru):
    WebInfos = {}
    global stop_run
    shiroCookie = {'rememberMe': '1'}
    headers = {
        "User-Agent": random.choice(USERAGENT.USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    }
    s = requests.Session()
    s.cookies.update(shiroCookie)
    while not q.empty():
        if daoru:
            x = q.get_nowait()
            host = x
            ip = ""
            prot = ""
            domain = ""
            server = ""
            fid = ""
        else:
            x = q.get_nowait()
            host = x[0]
            ip = x[2]
            prot = x[3]
            domain = x[4]
            server = x[5]
            fid = x[6]
        if stop_run:
            break
        try:
            r = s.get(host, headers=headers, timeout=5, verify=False)
            webHeaders = r.headers
            try:
                webCodes = r.content.decode('utf-8')
            except UnicodeDecodeError:
                webCodes = r.content.decode('gbk', 'ignore')
            WebInfos[host] = webHeaders, webCodes, r.status_code, r.cookies.get_dict()
            try:
                html = r.content
                soup = BeautifulSoup(html, 'html.parser')
                global a
                a = soup.find_all('title')
                title = a[0].string.strip()
            except:
                title = "获取失败"

            r.close()
            if brute == "开启敏感目录":
                if a:
                    b.put(host)
                elif r.status_code != 404:
                    b.put(host)
                Label_4.config(text="进行敏感扫描中")
                Backup(b, host)

            else:
                if a:
                    testhost = []
                    for rule in ruleDatas:
                        cms = rule[0]
                        rulesRegex = rule[2]
                        if 'headers' == rule[1]:
                            resHeads = re.findall(rulesRegex, str(webHeaders))
                            if resHeads:
                                testhost.append(host)
                                if host in testhost and len(testhost) != 1:
                                    continue
                                else:
                                    result(host, title, ip, prot, domain, server, fid, '', cms)
                        elif 'cookie' == rule[1]:
                            for key in list(WebInfos):
                                for cookie in WebInfos[key][3]:
                                    resCookies = re.findall(rulesRegex, cookie)
                                    if resCookies:
                                        testhost.append(host)
                                        if host in testhost and len(testhost) != 1:
                                            continue
                                        else:
                                            result(host, title, ip, prot, domain, server, fid, '', cms)

                        elif 'code' == rule[1]:
                            resCodes = re.findall(rulesRegex, webCodes)
                            if resCodes:
                                testhost.append(host)
                                if host in testhost and len(testhost) != 1:
                                    continue
                                else:
                                    result(host, title, ip, prot, domain, server, fid, '', cms)

                elif r.status_code != 404:
                    testhost = []
                    for rule in ruleDatas:
                        cms = rule[0]
                        rulesRegex = rule[2]
                        if 'headers' == rule[1]:
                            resHeads = re.findall(rulesRegex, str(webHeaders))
                            if resHeads:
                                testhost.append(host)
                                if host in testhost and len(testhost) != 1:
                                    continue
                                else:
                                    result(host, title, ip, prot, domain, server, fid, '', cms)

                        elif 'cookie' == rule[1]:
                            for key in list(WebInfos):
                                for cookie in WebInfos[key][3]:
                                    resCookies = re.findall(rulesRegex, cookie)
                                    if resCookies:
                                        testhost.append(host)
                                        if host in testhost and len(testhost) != 1:
                                            continue
                                        else:
                                            result(host, title, ip, prot, domain, server, fid, '', cms)

                        elif 'code' == rule[1]:
                            resCodes = re.findall(rulesRegex, webCodes)
                            if resCodes:
                                testhost.append(host)
                                if host in testhost and len(testhost) != 1:
                                    continue
                                else:
                                    result(host, title, ip, prot, domain, server, fid, '', cms)

                elif r.status_code == 404 or r.status_code == 403:
                    if 'Whitelabel Error Page' in r.text or 'There was an unexpected error' in r.text:
                        result(host, title, ip, prot, domain, server, fid, '', "spring boot")


        except:
            traceback.print_exc()

    if int(comboxlist2.get()) >= 500:
        time.sleep(10)
    if int(comboxlist2.get()) < 500:
        time.sleep(5)
    if brute != "开启敏感目录":
        Label_4.config(text="标签扫描结束")
    else:
        Label_4.config(text="目录扫描结束")


def EnterpriseArchitectur_o(id):
    new_num()
    x = tree.get_children()
    for item in x:
        tree.delete(item)
    tree.heading('1', text="序号")
    tree.heading('2', text='详情URL')
    tree.heading('3', text='控股比例')
    tree.heading('4', text='公司名字')
    tree.column('1', width=250, anchor='center')
    tree.column('2', width=550, anchor='center')
    tree.column('3', width=150, anchor='center')
    tree.column('4', width=300, anchor='center')
    Allinall = EnterpriseArchitecture.aaa(id)
    for i in Allinall:
        hui = i.split(':')
        result("https://www.qcc.com/web/search?key=" + hui[0], hui[1], hui[0], "", "", "", "", "")


def EnterpriseArchitecture_execute():
    global QueryEnterpriseName
    QueryEnterpriseName = e1.get().strip()
    id = EnterpriseArchitecture.get_name(QueryEnterpriseName)
    try:
        EnterpriseArchitectur_o(id)
    except:
        e2.insert('end', "获取失败" + "\n")


def EnterpriseArchitecture_UI():
    global e1
    global top
    top = Toplevel()
    top.title('股权穿透')
    top.wm_attributes("-topmost", 1)
    top.geometry("400x100+550+250")
    top.resizable(width=False, height=False)
    L1 = ttk.Label(top, text="企业全称:", font=("宋体", 9))
    L1.place(relx=0.020, rely=0.180, relwidth=0.30, relheight=0.30)
    e1 = ttk.Entry(top)
    e1.place(relx=0.2, rely=0.25, relwidth=0.600, relheight=0.2)
    c = ttk.Button(top, text="搜索", command=EnterpriseArchitecture_execute)
    c.place(relx=0.820, rely=0.22, relwidth=0.140, relheight=0.25)


def sizeHuman(num):
    base = 1024
    for x in ['B ', 'KB', 'MB', 'GB']:
        if base > num > -base:
            return "%3.0f%s" % (num, x)
        num /= base
    return "%3.0f%s" % (num, 'TB')


def compare_rule(rule, response_status, response_html, response_content_type):
    rule_status = [200, 206, rule.get('status')]
    if response_status == 404 or "<title>404" in response_html or "您要查找的资源可能已被删除" in response_html or "找不到" in response_html or "HTTP Error 404" in response_html or "page not found" in response_html or "404错误提示" in response_html or "404 Not Found" in response_html or "Error report" in response_html or "404 - Not Found" in response_html:
        return
    if rule.get('status') and (response_status not in rule_status):
        return
    if rule.get('tag') and (rule['tag'] not in response_html):
        return
    if rule.get('type_no') and (rule['type_no'] in response_content_type):
        return
    if rule.get('type') and (rule['type'] not in response_content_type):
        return
    return True


def Backup(b, host):
    TestRecord = []
    tree.heading('1', text="序号")
    tree.heading('2', text='URL')
    tree.heading('3', text='path')
    tree.heading('4', text='size')
    tree.column('1', width=250, anchor='center')
    tree.column('2', width=600, anchor='center')
    tree.column('3', width=257, anchor='center')
    tree.column('4', width=150, anchor='center')
    all_rules = []
    config_file_rules = rules_path.common_rules.get('config_file')
    shell_scripts_rules = rules_path.common_rules.get('shell_scripts')
    editor_rules = rules_path.common_rules.get('editor')
    spring_rules = rules_path.common_rules.get('spring')
    web_app_rules = rules_path.common_rules.get('web_app')
    other_rules = rules_path.common_rules.get('other')
    all_rules += config_file_rules
    all_rules += shell_scripts_rules
    all_rules += editor_rules
    all_rules += spring_rules
    all_rules += web_app_rules
    all_rules += other_rules
    Mark = {}
    while not b.empty():
        u = b.get_nowait()
        Mark[u] = False
        print(Mark)
        user_agent = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36'
        headers = {'User-Agent': user_agent, 'Connection': 'Keep-Alive', 'Range': 'bytes=0-102400'}
        for i in range(0, len(all_rules) - 1):
            TestRecord.append(u)
            try:
                r = requests.get(url=u + all_rules[i]["path"], headers=headers, verify=False, timeout=3)
                size = len(r.text)
                response_status = r.status_code
                response_html = r.text
                response_content_type = r.headers['Content-Type']
                print(u + all_rules[i]["path"] + " || " + str(response_status))
                if compare_rule(all_rules[i], response_status, response_html, response_content_type):
                    result(host, all_rules[i]["path"], size, "", "", "", "")
                    Mark[u] = True
                elif TestRecord.count(u) == len(all_rules) - 1 and Mark[u] == False:
                    result(host, "False", "False", "", "", "", "")
            except:
                print("Error")


def MakingSearch_GUI():
    new_num()
    global e1
    global top
    top = Toplevel()
    top.title('github搜索')
    top.wm_attributes("-topmost", 1)
    top.geometry("400x100+550+250")
    top.resizable(width=False, height=False)
    L1 = ttk.Label(top, text="关键字:", font=("宋体", 9))
    L1.place(relx=0.020, rely=0.180, relwidth=0.30, relheight=0.30)
    e1 = ttk.Entry(top)
    e1.place(relx=0.2, rely=0.25, relwidth=0.600, relheight=0.2)
    c = ttk.Button(top, text="搜索", command=MakingSearch)
    c.place(relx=0.820, rely=0.22, relwidth=0.140, relheight=0.25)


def MakingSearch():
    x = tree.get_children()
    for item in x:
        tree.delete(item)
    tree.heading('1', text="序号")
    tree.heading('2', text='URL')
    tree.heading('3', text='关键字')
    tree.heading('4', text="误报")
    tree.column('1', width=150, anchor='center')
    tree.column('2', width=720, anchor='center')
    tree.column('3', width=200, anchor='center')
    tree.column('4', width=200, anchor='center')
    query = e1.get()
    hosts = query.split(',')
    for i in range(0, len(hosts)):
        hosts.append(hosts[i] + " @")
    print(hosts)
    keywords = GenerateKeywords(hosts)
    github_test = Github(github_token)
    for key in keywords:
        result = github_test.search_code(
            key,
            sort="indexed",
            order="desc",
        )
        _analysis_page(result, key)


def result(host, title, ip, port, domain, server, fid, backup=None, Fingerprint=None):
    global num
    li = [num, host, title, ip, port, domain, server, fid, backup, Fingerprint]
    num = int(num) + 1
    if (num % 2) == 0:
        tree.insert('', 'end', values=li, tags=('oddrow',))
    else:
        tree.insert('', 'end', values=li)


def update_result(host, title, ip, port, domain, server, backup=None, Fingerprint=None):
    global num
    li = [num, host, title, ip, port, domain, server, backup, Fingerprint]
    num = int(num) + 1
    if (num % 2) == 0:
        tree.insert('', 'end', values=li, tags=('oddrow',))
        tree.update()
    else:
        tree.insert('', 'end', values=li)
        tree.update()


def save():
    li = []
    file_path = filedialog.asksaveasfilename(initialdir=os.path.abspath('.'), title=u'保存文件',
                                             filetypes=[('csv File', '.csv')])
    f = open(file_path + '.csv', 'a+', encoding='utf_8_sig', newline='')
    winter = csv.writer(f)
    column = ['序号', 'HOST', '', '', '', '', '', '', '']
    winter.writerow(column)
    for row_id in tree.get_children():
        row = tree.item(row_id)
        li.append(row['values'])
    winter.writerows(li)


def ar():
    if h11.get() == 0:
        h11.set(1)
    elif h11.get() == 1:
        h11.set(0)


def sr():
    if h12.get() == 0:
        h12.set(1)
    elif h12.get() == 1:
        h12.set(0)


def tr():
    if h13.get() == 0:
        h13.set(1)

    elif h13.get() == 1:
        h13.set(0)


def dr():
    if h14.get() == 0:
        h14.set(1)

    elif h14.get() == 1:
        h14.set(0)


def load_ui():
    global item_text
    global num
    global stop_run
    global tree
    global menu
    global Label_4
    global Entry_1
    global comboxlist2
    global comboxlist1
    global Checkbutton_2
    global Checkbutton_1
    global Entry_11
    global h11

    item_text = []
    num = 1
    stop_run = False
    Label_1 = ttk.Label(win, text="FOFA语法", font=("黑体", 11))
    Label_1.place(relx=0.020, rely=0.030, relwidth=0.100, relheight=0.050)

    h11 = IntVar()
    Checkbutton_121 = ttk.Checkbutton(win, text="排除干扰", variable=h11, offvalue=0, command=ar)
    Checkbutton_121.place(relx=0.040, rely=0.089, relwidth=0.090, relheight=0.040)

    var1 = StringVar()
    comboxlist1 = ttk.Combobox(win, textvariable=var1)
    comboxlist1['values'] = ('50', '100', '300', '500', '1000')
    comboxlist1.current(0)
    comboxlist1.place(relx=0.780, rely=0.025, relwidth=0.050, relheight=0.040)
    var2 = StringVar()
    comboxlist2 = ttk.Combobox(win, textvariable=var2)
    comboxlist2['values'] = ('100', '500', '1000', '5000', '10000')
    comboxlist2.current(2)
    comboxlist2.place(relx=0.780, rely=0.085, relwidth=0.050, relheight=0.040)

    Label_2 = ttk.Label(win, text="thread:", font=("宋体", 11))
    Label_2.place(relx=0.720, rely=0.032, relwidth=0.060, relheight=0.030)
    Label_3 = ttk.Label(win, text="number:", font=("宋体", 11))
    Label_3.place(relx=0.720, rely=0.092, relwidth=0.060, relheight=0.030)
    Label_4 = ttk.Label(win, text='', font=("宋体", 10))
    Label_4.place(relx=0.014, rely=0.950, relwidth=0.12, relheight=0.040)
    Entry_11 = ttk.Entry(win)
    Entry_11.insert('0', Entry_1.get())
    Entry_11.place(relx=0.110, rely=0.028, relwidth=0.480, relheight=0.050)
    h1 = StringVar()
    h2 = StringVar()
    Checkbutton_1 = ttk.Combobox(win, textvariable=h1, state="readonly")
    Checkbutton_1['values'] = ('开启敏感目录', '关闭敏感目录')
    Checkbutton_1.current(1)
    Checkbutton_1.place(relx=0.630, rely=0.089, relwidth=0.090, relheight=0.040)

    Checkbutton_2 = ttk.Combobox(win, textvariable=h2, state="readonly")
    Checkbutton_2['values'] = ('开启标签过滤', '关闭标签过滤')
    Checkbutton_2.current(1)
    Checkbutton_2.place(relx=0.630, rely=0.029, relwidth=0.090, relheight=0.040)
    Button_11 = ttk.Button(win, text="Query", command=fofa)
    Button_11.place(relx=0.845, rely=0.02, relwidth=0.060, relheight=0.10)
    Button_2 = ttk.Button(win, text="Stop", command=stop)
    Button_2.place(relx=0.920, rely=0.02, relwidth=0.060, relheight=0.05)
    Button_3 = ttk.Button(win, text="export", command=save)
    Button_3.place(relx=0.920, rely=0.08, relwidth=0.060, relheight=0.05)
    col = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    tree = ttk.Treeview(win, columns=col, height=10, show="headings")
    style = ttk.Style()
    style.theme_create("st_app", parent="vista", settings={
        ".": {"configure": {"background": "SystemButtonFace", "foreground": 'SystemWindowText',
                            "selectbackground": "SystemHighlightText", "selectforeground": "SystemHighlight",
                            "insertcolor": "SystemWindowText", "font": "TkDefaultFont"}},
        "Treeview": {"configure": {}, "map": {"background": [("selected", "SystemHighlight")]}},
        "TCombobox": {"configure": {"padding": "1"}},
        "TButton": {"configure": {"anchor": "center", "padding": 1, "font": ("宋体", 10)}},
        "TCheckbutton": {"configure": {"padding": 2, "font": ("宋体", 11)}}
    })
    style.theme_use("st_app")
    style.configure('Treeview.Heading', font=("黑体", 9), foreground='red')
    style.configure('Treeview', font=("宋体", 10))
    tree.bind('<3>', treeviewClick)
    tree.tag_configure('oddrow', background='white')
    menu = Menu(win, tearoff=False)
    menu.add_command(label="复制URL", command=copyURL)
    menu.add_command(label="复制第三行", command=copyIP)
    menu.add_command(label="复制第四行", command=copybackup)
    menu.add_command(label="复制Fid", command=copyFid)
    # 'fid="'+item_text[7]+'"'
    menu.add_command(label="Fid总数量",
                     command=lambda: fidcount.fid_UI(fofa_email, fofa_key, 'fid="' + item_text[7] + '"'))
    menu.add_command(label="域名反查机制", command=lambda: DomainContras.edu_ui(item_text[1]))
    menu.add_command(label="证书信息查询", command=lambda: SSLQ.cer_ui(item_text[1]))
    menu.add_command(label="解析记录查询", command=lambda: ParseRecord.PA_UI(item_text[1]))

    tree.bind('<Double-Button-1>', gourl)
    tree.place(relx=0.020, rely=0.140, relwidth=0.950, relheight=0.800)
    # 滚动条
    menu1.add_command(label="股权穿透", command=EnterpriseArchitecture_UI)
    menu1.add_separator()
    menu1.add_command(label="Github目标收集", command=MakingSearch_GUI)
    menu1.add_separator()
    menu1.add_command(label="google搜集", command=google_help)
    menu1.add_separator()
    menu1.add_command(label="导入资产", command=ImportAssets_ui)
    menu1.add_separator()
    menu1.add_command(label="WeXin", command=weixin_help)
    menu1.add_separator()
    VScroll1 = Scrollbar(win, orient='vertical', command=tree.yview)
    VScroll1.place(relx=0.970, rely=0.140, relwidth=0.014, relheight=0.800)
    tree.configure(yscrollcommand=VScroll1.set)


def ImportAssets_ui():
    global e1
    global top
    global Checkbutton_212

    top = Toplevel()
    top.title('导入资产')
    top.wm_attributes("-topmost", 1)
    top.geometry("400x100+550+250")
    top.resizable(width=False, height=False)
    L1 = ttk.Label(top, text="目标文件:", font=("宋体", 9))
    L1.place(relx=0.020, rely=0.180, relwidth=0.30, relheight=0.30)
    e1 = ttk.Entry(top)
    e1.place(relx=0.2, rely=0.25, relwidth=0.600, relheight=0.2)
    c = ttk.Button(top, text="导入", command=impor_file)
    c.place(relx=0.820, rely=0.22, relwidth=0.140, relheight=0.25)

    h212 = StringVar()
    Checkbutton_212 = ttk.Combobox(top, textvariable=h212, state="readonly")
    Checkbutton_212['values'] = ('开启标签过滤', '开启敏感目录')
    Checkbutton_212.place(relx=0.2, rely=0.65, relwidth=0.600, relheight=0.2)


def impor_file():
    e1.delete(0, 'end')
    filePath = filedialog.askopenfilename()
    e1.insert("end", filePath + '\n')
    ImportAssets_execute()


def ImportAssets_execute():
    t = []
    new_num()
    x = tree.get_children()
    for item in x:
        tree.delete(item)
    filename = e1.get().strip()

    print(Checkbutton_212.get())
    if Checkbutton_212.get() != "":
        Label_4.config(text="正在获取数据...")
        q = queue.Queue()
        b = queue.Queue()
        daoru = True
        with open(filename, "r") as f:
            for i in f.readlines():
                if 'http' in i:
                    pass
                else:
                    if ':443' in i[0]:
                        i = 'https://' + i
                    else:
                        i = 'http://' + i
                q.put(i)
            for i in range(50):
                thread = threading.Thread(target=spider, args=(q, b, Checkbutton_212.get(), daoru))
                t.append(thread)
            for i in range(50):
                t[i].start()

    else:
        with open(filename, "r") as f:
            for i in f.readlines():
                if 'http' in i:
                    pass
                else:
                    if ':443' in i[0]:
                        i = 'https://' + i
                    else:
                        i = 'http://' + i
                update_result(i.strip() + "", "", "", "", "", "", "")


def SearchGood_look():
    global fofa_email
    global fofa_key
    global github_token
    global domainss2
    global win
    global Entry_1
    global menbar
    global menu1
    global menu2
    global menu3
    global proxies
    global h12
    global h13
    global menu1
    global h14

    proxies = {'http': None, 'https': None}
    with open('config/configs.json', 'r')as fp:
        json_data = json.load(fp)
        fofa_email = json_data['fofa_email']
        fofa_key = json_data['fofa_key']
        github_token = json_data['github_token']
        domainss2 = json_data['google_profiex']

    win = Tk()
    win.withdraw()
    win = ThemedTk(theme="arc", toplevel=True, themebg=True)
    win.title('NetworkSecurity pro+ https://github.com/YanMu2020[Windows试验版]')
    win.geometry("1320x700+350+150")
    menbar = Menu(win, tearoff=0)
    menbar.add_command(label="证书序列号", command=Certificatecheck.CERTIFICATE_SERIAL_NUMBER)
    menbar.add_command(label="Js_MD5", command=JSCheck.JS_MD5_CALCULATION)
    menbar.add_command(label="ICON", command=iconCheck.create)
    menbar.add_command(label="子域名转C段", command=SUBDOMAIN.SUBDOMAIN_TRANSFORMATION_C_SEGMENT)
    menbar.add_command(label="IP386", command=ipi.IP386_QUERY)
    menbar.add_command(label="zoomeye域名关联", command=zoomeyen.zoomeye_UI)
    menbar.add_command(label="securitytrails子域名", command=DNSSub.DNS_UI)
    menu1 = Menu(win, tearoff=0)
    menu1 = Menu(win, tearoff=0)
    menu1.add_command(label="edu网段查询", command=edui.edu_ui)
    menu1.add_separator()
    menu1.add_command(label="截图", command=AScreenshot.AS_ui)
    menu1.add_separator()
    menu1.add_command(label="crawlergo", command=Tools.crawlergo_ui)
    menu1.add_separator()
    menu1.add_command(label="WebCrack检测", command=Tools.webcrack_ui)
    menu1.add_separator()
    menu1.add_command(label="mssql bypass转换", command=bypassWAF.bypassweb_ui)
    menu1.add_separator()
    menu1.add_command(label="启动端口弱口令检测工具", command=Tools.SuperWeakPassword)
    menu1.add_separator()
    menu2 = Menu(win, tearoff=0)
    menu2.add_separator()
    menbar.add_cascade(label="其他功能", menu=menu1)
    win.config(menu=menbar)

    h12 = IntVar()
    Checkbutton_122 = ttk.Checkbutton(win, text="fofa", variable=h12, offvalue=0, command=sr)
    Checkbutton_122.place(relx=0.340, rely=0.289, relwidth=0.090, relheight=0.040)

    h13 = IntVar()
    Checkbutton_123 = ttk.Checkbutton(win, text="google", variable=h13, offvalue=0, command=tr)
    Checkbutton_123.place(relx=0.440, rely=0.289, relwidth=0.090, relheight=0.040)

    h14 = IntVar()
    Checkbutton_123 = ttk.Checkbutton(win, text="WeChat", variable=h14, offvalue=0, command=dr)
    Checkbutton_123.place(relx=0.540, rely=0.289, relwidth=0.090, relheight=0.040)

    Entry_1 = ttk.Entry(win)
    Entry_1.place(relx=0.220, rely=0.350, relwidth=0.480, relheight=0.070)
    Button_1 = ttk.Button(win, text="Query", command=SpaceToChoose)
    Button_1.place(relx=0.745, rely=0.350, relwidth=0.060, relheight=0.070)
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
    win.protocol("WM_DELETE_WINDOW", on_closing)
    win.mainloop()


def fofa_tree():
    tree.column('1', width=80, anchor='center')
    tree.column('2', width=190, anchor='center')
    tree.column('3', width=190, anchor='center')
    tree.column('4', width=120, anchor='center')
    tree.column('5', width=60, anchor='center')
    tree.column('6', width=120, anchor='center')
    tree.column('7', width=120, anchor='center')
    tree.column('8', width=120, anchor='center')
    tree.column('9', width=128, anchor='center')
    tree.column('10', width=130, anchor='center')
    tree.heading('1', text='序号')
    tree.heading('2', text='HOST')
    tree.heading('3', text='标题')
    tree.heading('4', text='IP')
    tree.heading('5', text='端口')
    tree.heading('6', text='域名')
    tree.heading('7', text='服务')
    tree.heading('8', text='Fid')
    tree.heading('9', text='path')
    tree.heading('10', text='标签')


@aswync
def weixin_hacker(search, page):
    x = tree.get_children()
    aas = ""
    assw = []

    for item in x:
        tree.delete(item)
    for i in range(1, page + 1):
        burp0_url = "https://weixin.sogou.com:443/weixin?query={}&type=2&page={}&ie=utf8".format(search, i)
        burp0_cookies = {"IPLOC": "CN3703", "SUID": "AD4B60DF6555A00A000000006121AD67",
                         "ld": "flllllllll2PwzCOYvpHBL9PrQqPwzCXTLxaryllll9llllxVklll5@@@@@@@@@@",
                         "cd": "1629597031&0dd631766d1e0335f80ef81d224e2f2d",
                         "rd": "flllllllll2PwzCOYvpHBL9PrQqPwzCXTLxaryllll9llllxVklll5@@@@@@@@@@",
                         "ABTEST": "0|1629614814|v1", "weixinIndexVisited": "1",
                         "SUV": "00F9E661DF604BAD6121F2DFB9457372", "SNUID": "96715BE43B3EF11A7F5391ED3BF6BE6F",
                         "JSESSIONID": "aaa-2ajD0rEj8fys7DtTx"}
        burp0_headers = {"Pragma": "no-cache", "Cache-Control": "no-cache",
                         "Sec-Ch-Ua": "\"Chromium\";v=\"92\", \" Not A;Brand\";v=\"99\", \"Microsoft Edge\";v=\"92\"",
                         "Sec-Ch-Ua-Mobile": "?0", "Upgrade-Insecure-Requests": "1",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.78",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                         "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Connection": "close"}
        response = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies).content
        source = etree.HTML(response)
        information = source.xpath('//h3/a/@href')
        keyword = source.xpath('//div[@class="s-p"]/a/text()')
        ka = source.xpath('//div[@class="txt-box"]/p//text()')

        for ss in ka:
            if ss.endswith('...'):
                assw.append(ss)
            else:
                ss = ss.replace("...", "")
                assw.append(ss)

        for i in assw:
            aas += i

        allink = aas.strip().split('...')[:-1]
        print(len(allink))
        print(allink)
        for i in range(0, len(information)):
            update_result("https://weixin.sogou.com/" + information[i], keyword[i], allink[i], "", "", "", "")
        assw.clear()
        allink.clear()
        aas = ""


def ea3():
    new_num()
    tree.heading('1', text="序号")
    tree.heading('2', text='URL')
    tree.heading('3', text='公众号')
    tree.heading('4', text='内容摘取')
    tree.column('1', width=50, anchor='center')
    tree.column('2', width=100, anchor='center')
    tree.column('3', width=100, anchor='center')
    tree.column('4', width=900, anchor='center')
    search = Entry_1.get()
    page = 1
    weixin_hacker(search, page)


def Weichat():
    load_ui()
    ea3()


def SpaceToChoose():
    if h12.get() and h13.get() and h14.get():
        display_messagebox2()
    elif h12.get():
        if h13.get() or h14.get():
            display_messagebox2()
        else:
            asdhahi()
    elif h13.get():
        if h12.get() or h14.get():
            display_messagebox2()
        else:
            google_help2()
    elif h14.get():
        if h12.get() or h13.get():
            display_messagebox2()
        else:
            Weichat()
    else:
        pass


def asdhahi():
    query = Entry_1.get()
    load_ui()
    fofa_tree()
    fields = "host,title,ip,port,domain,server,fid"
    query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    count = 100
    r = requests.get(
        url="https://fofa.so/api/v1/search/all?email={}&key={}&fields={}&qbase64={}&size={}".format(fofa_email,
                                                                                                    fofa_key, fields,
                                                                                                    query, count),
        proxies=proxies)
    data = json.loads(r.text.encode("GBK", 'ignore').decode('GBK'))
    for i in data['results']:
        if 'http' in i[0]:
            host = i[0]
        else:
            if ':443' in i[0]:
                host = 'https://' + i[0]
            else:
                host = 'http://' + i[0]
        title = i[1].strip()
        ip = i[2]
        prot = i[3]
        domain = i[4]
        server = i[5]
        fid = i[6]
        result(host, title, ip, prot, domain, server, fid, '', '')