import base64
import configparser
import json
import os
import queue
import tkinter as tk
import webbrowser
from tkinter import ttk

import requests
from ttkbootstrap import Style

from Plugins import ICON, IP138


def login_ui():
    global menu
    global tree
    global Label_2
    global Entry_1
    global num
    global item_text
    global stop_run
    global h1

    # cf = configparser.ConfigParser()
    # cf.read("./iniFile/config.ini")
    # secs = cf.sections()
    # email = cf.get('fofa api', 'EMAIL')
    # key = cf.get('fofa api', 'KEY')

    item_text = []
    num = 1
    stop_run = False

    window = tk.Tk()

    window.title('Weapon by zjhzjhhh v1.0 ')
    window.geometry('1350x700+350+150')

    menbar = tk.Menu(window,tearoff=0)
    menbar.add_command(label="ICON", command=ICON.create)#, command=ICON.create()
    menbar.add_command(label="IP反查", command=IP138.IP138_search)#, command=IP138.IP138_search()
    menbar.add_command(label="弱口令检测")#, command=

    window.config(menu = menbar)

    h1 = tk.IntVar()
    Checkbutton_1 = ttk.Checkbutton(window, text="排除干扰", variable=h1, offvalue=0,command=interfere)
    Checkbutton_1.place(relx=0.040, rely=0.089, relwidth=0.090, relheight=0.040)

    Label_1 = ttk.Label(window, text="FOFA语法", font=("黑体", 11))
    Label_1.place(relx=0.020, rely=0.030, relwidth=0.100, relheight=0.050)

    Label_2 = ttk.Label(window, text='', font=("宋体", 10))
    Label_2.place(relx=0.014, rely=0.950, relwidth=0.12, relheight=0.040)

    Entry_1 = ttk.Entry(window)
    Entry_1.place(relx=0.110, rely=0.028, relwidth=0.480, relheight=0.050)

    Button_1 = ttk.Button(window,text="Query", command=fofa)#, command=fofa
    Button_1.place(relx = 0.845,rely =0.02,relwidth = 0.060,relheight = 0.11)

    Button_2 = ttk.Button(window, text="Stop")#, command=stop
    Button_2.place(relx = 0.920,rely=0.02,relwidth = 0.060,relheight = 0.05)

    Button_3 = ttk.Button(window, text="Export")#, command=save
    Button_3.place(relx = 0.920,rely= 0.08,relwidth = 0.060,relheight = 0.05)

    col = [1, 2, 3, 4, 5, 6, 7, 8]
    tree = ttk.Treeview(window, columns=col, height=10, show="headings")

    style = Style(theme="yeti")
    print(style.theme_names())
    style.theme_create( "st_app", parent="vista",settings={
        ".":{"configure":{"background":"SystemButtonFace","foreground": 'SystemWindowText',"selectbackground":"SystemHighlightText","selectforeground":"SystemHighlight","insertcolor":"SystemWindowText","font":"TkDefaultFont"}},
        "Treeview":{"configure":{},"map":{"background":[("selected","SystemHighlight")]}},
        "TCombobox":{"configure":{"padding":"1"}},
        "TButton":{"configure":{"anchor":"center","padding":1,"font":("宋体",10)}},
        "TCheckbutton":{"configure":{"padding":2,"font":("宋体",11)}}
        })
    style.theme_use("st_app")
    style.configure('Treeview.Heading', font=("黑体", 10), foreground='black')
    style.configure('Treeview', font=("宋体", 10))

    tree.column('1',width=80,anchor='center')
    tree.column('2',width=190,anchor='center')
    tree.column('3',width=190,anchor='center')
    tree.column('4',width=120,anchor='center')
    tree.column('5',width=60,anchor='center')
    tree.column('6',width=120,anchor='center')
    tree.column('7',width=120,anchor='center')
    tree.column('8',width=120,anchor='center')
    # tree.column('9',width=128,anchor='center')
    # tree.column('10',width=130,anchor='center')
    tree.heading('1',text='序号')
    tree.heading('2',text='HOST')
    tree.heading('3',text='标题')
    tree.heading('4',text='IP')
    tree.heading('5',text='端口')
    tree.heading('6',text='域名')
    tree.heading('7',text='服务')
    tree.heading('8',text='备份')
    # tree.heading('9',text='path')
    # tree.heading('10',text='标签')
    tree.bind('<3>', treeviewClick)
    tree.tag_configure('oddrow',background='white')
    menu = tk.Menu(window, tearoff=False)
    menu.add_command(label="复制URL")#, command=copyURL
    menu.add_command(label="复制IP")#, command=copyIP
    menu.add_command(label="复制备份")#, command=copybackup
    tree.bind('<Double-Button-1>',gourl)
    tree.place(relx = 0.020,rely =0.140,relwidth = 0.950,relheight =0.800)
    VScroll1 = tk.Scrollbar(window, orient='vertical', command=tree.yview)
    VScroll1.place(relx=0.970, rely=0.140, relwidth=0.014, relheight=0.800)
    tree.configure(yscrollcommand=VScroll1.set)
    window.protocol("WM_DELETE_WINDOW", on_closing)


    window.mainloop()


def fofa():
    global num
    global stop_run

    proxies = {'http': None, 'https': None}
    cf = configparser.ConfigParser()
    cf.read("./config/config.ini")
    fofa_email = cf.get('fofa api', 'EMAIL')
    fofa_key = cf.get('fofa api', 'KEY')


    t = []
    stop_run = False
    num = 1
    count=10000

    x = tree.get_children()
    for item in x:
        tree.delete(item)
    query = Entry_1.get()
    fields = "host,title,ip,port,domain,server"
    query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    r=requests.get(url="https://fofa.so/api/v1/search/all?email={}&key={}&fields={}&qbase64={}&size={}".format(fofa_email,fofa_key,fields,query,count), proxies=proxies)
    data = json.loads(r.text.encode("GBK", 'ignore').decode('GBK'))
    for i in data['results']:
        if 'http' in i[0]:
            host=i[0]
        else:
            if ':443' in i[0]:
                host='https://'+i[0]
            else:
                host='http://'+i[0]
        title = i[1].strip()
        ip = i[2]
        prot = i[3]
        domain = i[4]
        server = i[5]
        result(host, title, ip, prot, domain, server, '')
    Label_2.config(text="扫描任务已结束")


def result(host,title,ip,port,domain,server,backup=None):
    global num
    li=[num,host,title,ip,port,domain,server,backup]
    # print(li)
    num=int(num)+1
    if (num % 2)==0:
        tree.insert('', 'end', values=li,tags=('oddrow',))

    else:
        tree.insert('', 'end', values=li)

def treeviewClick(event):
    global item_text
    menu.post(event.x_root, event.y_root)
    for item in tree.selection():
        item_text = tree.item(item,"values")
        return item_text

def gourl(event):
    for item in tree.selection():
        item_text = tree.item(item,"values")
        webbrowser.open(item_text[1])

def on_closing():
    os._exit(0)

##排除干扰
def interfere():
    if h1.get()==0:
        h1.set(1)
    elif h1.get() ==1:
        h1.set(0)

if __name__ == '__main__':
    login_ui()

