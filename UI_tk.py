import base64
import configparser
import ctypes
import json

import os
import queue
import threading
import tkinter as tk
import webbrowser


from tkinter import ttk, messagebox

import Function
from Function import new_num
import requests
from ttkthemes import ThemedTk




def search_ui():
    global fofa_email
    global fofa_key
    global github_token
    global domainss2
    global Entry_1
    global menbar
    global menu2
    global menu3
    global proxies
    global h12
    global h13
    global menu1
    global h14
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


    window = tk.Tk()
    window.withdraw()
    window = ThemedTk(theme="arc", toplevel=True, themebg=True)
    window.title("test_v1.0")
    window.geometry('1350x700+350+150')

    menbar = tk.Menu(window, tearoff=0)
    menbar.add_command(label = 'ICON')
    menbar.add_command(label='securitytrails子域名')
    menbar.add_command(label='oneforall')
    menbar.add_command(label='subdomain')
    menbar.add_command(label='edu网段查询')
    menbar.add_command(label='crawlergo')
    menbar.add_command(label='WebCrack检测')
    menbar.add_command(label='端口弱口令检测')
    menbar.add_command(label='xray_rad')
    menbar.add_command(label='爬虫')
    menbar.add_command(label='漏洞扫描')

    window.config(menu=menbar)

    item_text = []
    num = 1
    stop_run = False
    Label_1 = ttk.Label(window, text="FOFA语法", font=("黑体", 11))
    Label_1.place(relx=0.020, rely=0.030, relwidth=0.100, relheight=0.050)

    h11 = tk.IntVar()
    Checkbutton_121 = ttk.Checkbutton(window, text="排除干扰", variable=h11, offvalue=0) #, command=ar
    Checkbutton_121.place(relx=0.040, rely=0.089, relwidth=0.090, relheight=0.040)

    var1 = tk.StringVar()
    comboxlist1 = ttk.Combobox(window, textvariable=var1)
    comboxlist1['values'] = ('50', '100', '300', '500', '1000')
    comboxlist1.current(0)
    comboxlist1.place(relx=0.780, rely=0.025, relwidth=0.050, relheight=0.040)
    var2 = tk.StringVar()
    comboxlist2 = ttk.Combobox(window, textvariable=var2)
    comboxlist2['values'] = ('100', '500', '1000', '5000', '10000')
    comboxlist2.current(2)
    comboxlist2.place(relx=0.780, rely=0.085, relwidth=0.050, relheight=0.040)

    Label_2 = ttk.Label(window, text="1:", font=("宋体", 11))
    Label_2.place(relx=0.720, rely=0.032, relwidth=0.060, relheight=0.030)
    Label_3 = ttk.Label(window, text="2:", font=("宋体", 11))
    Label_3.place(relx=0.720, rely=0.092, relwidth=0.060, relheight=0.030)
    Label_4 = ttk.Label(window, text='dasd', font=("testtest", 10))
    Label_4.place(relx=0.014, rely=0.950, relwidth=0.12, relheight=0.040)
    Entry_1 = ttk.Entry(window)
    Entry_11 = ttk.Entry(window)
    Entry_11.insert('0', Entry_1.get())
    Entry_11.place(relx=0.110, rely=0.028, relwidth=0.480, relheight=0.050)
    h1 = tk.StringVar()
    h2 = tk.StringVar()
    Checkbutton_1 = ttk.Combobox(window, textvariable=h1, state="readonly")
    Checkbutton_1['values'] = ('1', '2')#开启敏感目录
    Checkbutton_1.current(1)
    Checkbutton_1.place(relx=0.630, rely=0.089, relwidth=0.090, relheight=0.040)

    Checkbutton_2 = ttk.Combobox(window, textvariable=h2, state="readonly")
    Checkbutton_2['values'] = ('1', '2') #开启标签过滤
    Checkbutton_2.current(1)
    Checkbutton_2.place(relx=0.630, rely=0.029, relwidth=0.090, relheight=0.040)
    Button_11 = ttk.Button(window, text="Query", command=fofa)
    Button_11.place(relx=0.845, rely=0.02, relwidth=0.060, relheight=0.10)
    Button_2 = ttk.Button(window, text="Stop")#, command=stop
    Button_2.place(relx=0.920, rely=0.02, relwidth=0.060, relheight=0.05)
    Button_3 = ttk.Button(window, text="export")#, command=save
    Button_3.place(relx=0.920, rely=0.08, relwidth=0.060, relheight=0.05)
    col = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    tree = ttk.Treeview(window, columns=col, height=10, show="headings")
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
    menu = tk.Menu(window, tearoff=False)
    menu.add_command(label="复制URL")#, command=copyURL
    menu.add_command(label="复制第三行")#, command=copyIP
    menu.add_command(label="复制第四行")#, command=copybackup
    menu.add_command(label="复制Fid")#, command=copyFid
    # 'fid="'+item_text[7]+'"'
    menu.add_command(label="Fid总数量")#, command=lambda: fidcount.fid_UI(fofa_email, fofa_key, 'fid="' + item_text[7] + '"')
    menu.add_command(label="域名反查机制")#, command=lambda: DomainContras.edu_ui(item_text[1])
    menu.add_command(label="证书信息查询")#, command=lambda: SSLQ.cer_ui(item_text[1])
    menu.add_command(label="解析记录查询")#, command=lambda: ParseRecord.PA_UI(item_text[1])

    tree.bind('<Double-Button-1>', gourl)
    tree.place(relx=0.020, rely=0.140, relwidth=0.950, relheight=0.800)
    # 滚动条
    menu1 = tk.Menu(window, tearoff=0)
    menu1.add_command(label="股权穿透")#, command=EnterpriseArchitecture_UI
    menu1.add_separator()
    menu1.add_command(label="Github目标收集")#, command=MakingSearch_GUI
    menu1.add_separator()
    menu1.add_command(label="google搜集")#, command=google_help
    menu1.add_separator()
    menu1.add_command(label="导入资产")#, command=ImportAssets_ui
    menu1.add_separator()
    menu1.add_command(label="WeXin")#, command=weixin_help
    menu1.add_separator()
    VScroll1 = tk.Scrollbar(window, orient='vertical', command=tree.yview)
    VScroll1.place(relx=0.970, rely=0.140, relwidth=0.014, relheight=0.800)
    tree.configure(yscrollcommand=VScroll1.set)




    window.protocol("WM_DELETE_WINDOW", on_closing)
    window.mainloop()


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

def fofaRun():

    proxies = {'http': None, 'https': None}
    cf = configparser.ConfigParser()
    cf.read("./config/config.ini")
    fofa_email = cf.get('fofa api', 'EMAIL')
    fofa_key = cf.get('fofa api', 'KEY')

    query = Entry_1.get()
    search_ui()
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


def fofa():

    proxies = {'http': None, 'https': None}
    cf = configparser.ConfigParser()
    cf.read("./config/config.ini")
    fofa_email = cf.get('fofa api', 'EMAIL')
    fofa_key = cf.get('fofa api', 'KEY')

    # if Checkbutton_2.get() == "开启标签过滤" and Checkbutton_1.get() == "开启敏感目录":
    #     Function.display_messagebox2()
    # else:
    fofa_tree()
    Label_4.config(text="正在获取数据...")
    global stop_run
    Function.new_num()
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
            Entry_11.delete(0, tk.END)
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
            # for i in range(th):
            #     thread = threading.Thread(target=spider, args=(q, b, Checkbutton_1.get(), daoru))
            #     t.append(thread)
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

def result(host, title, ip, port, domain, server, fid, backup=None, Fingerprint=None):
    global num
    li = [num, host, title, ip, port, domain, server, fid, backup, Fingerprint]
    num = int(num) + 1
    if (num % 2) == 0:
        tree.insert('', 'end', values=li, tags=('oddrow',))
    else:
        tree.insert('', 'end', values=li)

def stop():
    global stop_run
    stop_run = True
    Label_4.config(text="正在终止线程...")

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

def on_closing():
    os._exit(0)


if __name__ == '__main__':
    search_ui()
