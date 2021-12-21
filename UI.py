import base64
import configparser
import csv
import json
import os
import threading
import tkinter as tk
import webbrowser
from zoomeye.sdk import ZoomEye
from tkinter import ttk, filedialog
from xml import etree

import requests
from lxml import html
from ttkbootstrap import Style

from Function import display_messagebox2, copyURL, copyIP, new_num
from Plugins import ICON, IP138, Google, WebCrack, Xray, DomainCheck


def aswync(f):
    def wrapper(*args, **kwargs):
        thr = threading.Thread(target=f, args=args, kwargs=kwargs)
        thr.start()
    return wrapper

def login_ui():
    global menu
    global tree
    global Label_2
    global Entry_1
    global num
    global item_text
    global stop_run
    global h11
    global p1
    global h1
    global h2
    global h3
    global h4
    global Button_1

    item_text = []
    num = 1
    stop_run = False

    window = tk.Tk()

    window.title('Weapon by zjhzjhhh v1.0 ')
    window.geometry('1350x700+350+150')

    menbar = tk.Menu(window,tearoff=0)
    menbar.add_command(label="ICON", command=ICON.create)
    menbar.add_command(label="IP反查", command=IP138.IP138_search)
    menbar.add_command(label="弱口令检测", command=WebCrack.webcrack_ui)
    menbar.add_command(label="Google", command=Google_search_ui)
    menbar.add_command(label="WeChat", command=WeChat_search_ui)
    menbar.add_command(label="漏洞探测")
    #menbar.add_command(label="Xray被动扫描", command=Xray_UI)



    window.config(menu = menbar)


    # h1 = tk.BooleanVar()
    # Checkbutton_1 = ttk.Checkbutton(window, text="fofa", variable=h1, offvalue=0)#
    # Checkbutton_1.place(relx=0.280, rely=0.089, relwidth=0.090, relheight=0.040)
    #
    # h2 = tk.BooleanVar()
    # Checkbutton_2 = ttk.Checkbutton(window, text="zoomeye", variable=h2, offvalue=0)#, command=zoomeye
    # Checkbutton_2.place(relx=0.480, rely=0.089, relwidth=0.090, relheight=0.040)
    #
    # h3 = tk.BooleanVar()
    # Checkbutton_3 = ttk.Checkbutton(window, text="quake", variable=h3, offvalue=0)#, command=quake
    # Checkbutton_3.place(relx=0.580, rely=0.089, relwidth=0.090, relheight=0.040)


    Label_1 = ttk.Label(window, text="语法", font=("黑体", 11))
    Label_1.place(relx=0.020, rely=0.030, relwidth=0.100, relheight=0.050)

    Label_2 = ttk.Label(window, text='', font=("宋体", 10))
    Label_2.place(relx=0.014, rely=0.950, relwidth=0.12, relheight=0.040)

    Entry_1 = ttk.Entry(window)
    Entry_1.place(relx=0.110, rely=0.028, relwidth=0.480, relheight=0.050)

    Button_1 = ttk.Button(window,text="Query", command=fofa)#, command=choose
    Button_1.place(relx = 0.845,rely =0.02,relwidth = 0.060,relheight = 0.11)

    Button_2 = ttk.Button(window, text="Stop", command=stop)
    Button_2.place(relx = 0.920,rely=0.02,relwidth = 0.060,relheight = 0.05)

    Button_3 = ttk.Button(window, text="Export", command=save)
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

    tree.heading('1',text='序号')
    tree.heading('2',text='HOST')
    tree.heading('3',text='标题')
    tree.heading('4',text='IP')
    tree.heading('5',text='端口')
    tree.heading('6',text='域名')
    tree.heading('7',text='服务')
    tree.heading('8',text='备份')

    tree.bind('<3>', treeviewClick)
    tree.tag_configure('oddrow',background='white')
    menu = tk.Menu(window, tearoff=False)
    menu.add_command(label="复制URL", command=copyURL)
    menu.add_command(label="复制IP", command=copyIP)
    menu.add_command(label="域名反查机制", command=lambda: DomainCheck.edu_ui(item_text[1]))
    #menu.add_command(label="Github搜集")

    tree.bind('<Double-Button-1>',gourl)
    tree.place(relx = 0.020,rely =0.140,relwidth = 0.950,relheight =0.800)
    VScroll1 = tk.Scrollbar(window, orient='vertical', command=tree.yview)
    VScroll1.place(relx=0.970, rely=0.140, relwidth=0.014, relheight=0.800)
    tree.configure(yscrollcommand=VScroll1.set)
    window.protocol("WM_DELETE_WINDOW", on_closing)


    window.mainloop()

# def choose():
#     if h1.get():
#         fofa()
#     elif h2.get():
#         zoomeye()
#     elif h3.get():
#         quake()
#     elif h1.get() and h2.get():
#         fofa()
#         zoomeye()
#     elif h1.get() and h3.get():
#         fofa()
#         quake()
#     elif h2.get() and h3.get():
#         zoomeye()
#         quake()
#     elif h1.get() and h2.get() and h3.get():
#         fofa()
#         zoomeye()
#         quake()
#     else:
#         display_messagebox2()


def zoomeye():
    pass

def quake():
    pass

def fofa():

    proxies = {'http': None, 'https': None}
    cf = configparser.ConfigParser()
    cf.read("./config/conf.ini")
    fofa_email = cf.get('fofa api', 'EMAIL')
    fofa_key = cf.get('fofa api', 'KEY')


    Label_2.config(text="正在获取数据...")
    global num
    global stop_run
    stop_run=False
    num=1
    x=tree.get_children()
    for item in x:
        tree.delete(item)
    query=Entry_1.get()
    count=10000
    fields="host,title,ip,port,domain,server"
    query=base64.b64encode(query.encode('utf-8')).decode('utf-8')
    r=requests.get(url="https://fofa.so/api/v1/search/all?email={}&key={}&fields={}&qbase64={}&size={}".format(fofa_email,fofa_key,fields,query,count),proxies=proxies)
    data=json.loads(r.text.encode("GBK",'ignore').decode('GBK'))

    for i in data['results']:
        if 'http' in i[0]:
            host=i[0]
        else:
            if ':443' in i[0]:
                host='https://'+i[0]
            else:
                host='http://'+i[0]
        title=i[1].strip()
        ip=i[2]
        prot=i[3]
        domain=i[4]
        server=i[5]
        result(host,title,ip,prot,domain,server,'')
    Label_2.config(text="扫描任务已结束")
# time.sleep(60)

def Google_search_ui():
    global proxies
    global e1
    global e2
    global search
    global page

    cf = configparser.ConfigParser()
    cf.read("./config/conf.ini")
    p = cf.get("google proxy", "proxy")
    proxies = {'http': "socks5://{}".format(p), 'https': "socks5://{}".format(p)}
    print(proxies)

    top = tk.Toplevel()
    top.title('google search')
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
    b = ttk.Button(top, text="查询", command=find1)
    b.place(relx=0.820, rely=0.090, relwidth=0.140, relheight=0.20)
    L2 = ttk.Label(top, text="提醒:多个关键字可以用+连接,结果自动保存在out目录下", font=("宋体", 9))
    L2.place(relx=0.020, rely=0.6, relwidth=0.9, relheight=0.20)

def find1():
    new_num()
    tree.heading('1',text="序号")
    tree.heading('2',text='URL')
    tree.column('1',width=150,anchor='center')
    tree.column('2',width=1200,anchor='center')
    search=e1.get()
    page=int(e2.get())
    Google_search(search,page)

@aswync
def Google_search(search,page):
    x=tree.get_children()
    for item in x:
        tree.delete(item)
    lists= Google.search(search, num_results=page, proxy=proxies)
    for i in lists:
        print(i)
        update_result(i,"","","","","","")
        with open(r"out/google_hack.txt", "a+") as f:
            f.write(i+'\n')


def WeChat_search_ui():
    global e1
    global e2
    global search
    global page
    top = tk.Toplevel()
    top.title('wechat搜集')
    top.wm_attributes("-topmost",1)
    top.geometry("400x150+550+250")
    top.resizable(width=False, height=False)
    L1=ttk.Label(top,text="关键字",font=("宋体",9))
    L1.place(relx = 0.020,rely =0.030,relwidth =0.30,relheight = 0.30)
    e1=ttk.Entry(top)
    e1.place(relx = 0.2,rely =0.10,relwidth = 0.600,relheight = 0.2)
    L2=ttk.Label(top,text="页数",font=("宋体",9))
    L2.place(relx = 0.020,rely =0.4,relwidth =0.3,relheight = 0.20)
    e2=ttk.Entry(top)
    e2.place(relx=0.2,rely=0.40,relwidth=0.600,relheight=0.2)
    b=ttk.Button(top,text="查询",command=find2)
    b.place(relx = 0.820,rely =0.090,relwidth = 0.140,relheight = 0.20)

def find2():
    new_num()
    tree.heading('1',text="序号")
    tree.heading('2',text='URL')
    tree.heading('3',text='公众号')
    tree.heading('4',text='内容获取')
    tree.column('1',width=50,anchor='center')
    tree.column('2',width=100,anchor='center')
    tree.column('3',width=100,anchor='center')
    tree.column('4',width=1100,anchor='center')
    search=e1.get()
    page=int(e2.get())
    Wechat_search(search,page)


def Wechat_search(search, page):
    x = tree.get_children()
    aas = ""
    assw = []

    for item in x:
        tree.delete(item)
    for i in range(1, page + 1):
        url = "https://weixin.sogou.com:443/weixin?query={}&type=2&page={}&ie=utf8".format(search, i)
        cookies = {"IPLOC": "CN3703", "SUID": "AD4B60DF6555A00A000000006121AD67",
                         "ld": "flllllllll2PwzCOYvpHBL9PrQqPwzCXTLxaryllll9llllxVklll5@@@@@@@@@@",
                         "cd": "1629597031&0dd631766d1e0335f80ef81d224e2f2d",
                         "rd": "flllllllll2PwzCOYvpHBL9PrQqPwzCXTLxaryllll9llllxVklll5@@@@@@@@@@",
                         "ABTEST": "0|1629614814|v1", "weixinIndexVisited": "1",
                         "SUV": "00F9E661DF604BAD6121F2DFB9457372", "SNUID": "96715BE43B3EF11A7F5391ED3BF6BE6F",
                         "JSESSIONID": "aaa-2ajD0rEj8fys7DtTx"}
        headers = {"Pragma": "no-cache", "Cache-Control": "no-cache",
                         "Sec-Ch-Ua": "\"Chromium\";v=\"92\", \" Not A;Brand\";v=\"99\", \"Microsoft Edge\";v=\"92\"",
                         "Sec-Ch-Ua-Mobile": "?0", "Upgrade-Insecure-Requests": "1",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.78",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                         "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", "Connection": "close"}
        response = requests.get(url, headers=headers, cookies=cookies).content
        source = html.etree.HTML(response)
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


def save():
    li=[]
    file_path=filedialog.asksaveasfilename(initialdir=os.path.abspath('.'),title=u'保存文件',filetypes=[('csv File','.csv')])
    f=open(file_path+'.csv','a+',encoding='utf_8_sig',newline='')
    winter=csv.writer(f)
    column=['序号','HOST','','','','','','','']
    winter.writerow(column)
    for row_id in tree.get_children():
        row=tree.item(row_id)
        li.append(row['values'])
    winter.writerows(li)

def stop():
    global stop_run
    stop_run=True
    Label_2.config(text="正在终止线程...")

def update_result(host,title,ip,port,domain,server,backup=None,Fingerprint=None):
    global num
    li=[num,host,title,ip,port,domain,server,backup,Fingerprint]
    num=int(num)+1
    if (num % 2)==0:
        tree.insert('', 'end', values=li,tags=('oddrow',))
        tree.update()
    else:
        tree.insert('', 'end', values=li)
        tree.update()



if __name__ == '__main__':
    login_ui()

