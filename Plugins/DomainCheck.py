import requests
from lxml import etree
from tkinter import Toplevel, ttk, Text
from urllib.parse import urlparse

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
}


def login_edu():
    e2.delete(0, 'end')
    baseurl = 'http://ip.tool.chinaz.com/'
    baseurl2 = "http://seo.chinaz.com/"
    baseurl3 = "https://beian.tianyancha.com/search/"
    domain = e1.get().strip()
    response = requests.get(url=baseurl + domain, headers=headers, timeout=5).content
    response2 = requests.get(url=baseurl2 + domain, headers=headers, timeout=5).content

    source2 = etree.HTML(response)
    source3 = etree.HTML(response2)

    ip_infomation = source2.xpath('//div[@class="WhwtdWrap bor-b1s col-gray03"]/span[2]/text()')
    ForRecord = source3.xpath('//i[@class="color-2f87c1"]/a[@href="//icp.chinaz.com/{}"]/text()'.format(domain))
    response3 = requests.get(url=baseurl3 + ForRecord[0], headers=headers, timeout=5).content

    source4 = etree.HTML(response3)
    OtherForRecord = source4.xpath('//span[@class="ranking-ym"]/text()')

    print(OtherForRecord)
    e2.insert("end", ip_infomation[0] + '\n')
    e5.insert("end", ForRecord[0] + '\n')
    for i in OtherForRecord:
        e6.insert("end", i + '\n')


def ip_C():
    e3.delete(0, 'end')
    ips = e2.get().strip()
    baseurl2 = "http://tool.chinaz.com/ipwhois?q="
    response = requests.get(url=baseurl2 + ips, headers=headers, timeout=5).content
    source2 = etree.HTML(response)
    ip_infomation = source2.xpath('//div[@class="IcpMain02 bor-t1s02"]/div[@class="pt20 pr20 pl20 fz16"]/text()')
    e3.insert("end", ip_infomation[5].replace(' ', '')[8:] + '\n')


def edu_c():
    e4.delete(0, 'end')
    C_EDU = e3.get()
    C_TEST = C_EDU.split("-")
    STARTING_POINT_C_SECTION = C_TEST[0]
    AT_END_PHASE_C = C_TEST[1]
    name1 = STARTING_POINT_C_SECTION[0:-2]
    name2 = AT_END_PHASE_C[0:-5]
    name4 = int(name1.split('.')[-1])
    name5 = int(name2.split('.')[-1])
    fofa_c = ""
    for i in range(name4, name5 + 1):
        fofa_e = name1.split('.')[0] + '.' + name1.split('.')[1] + "." + str(i) + "." + "0/24"
        fofa_c += "ip=\"" + fofa_e + "\" || "
    e4.insert("end", fofa_c[:-3] + '\n')


def edu_ui(aim):
    global e1
    global e2
    global e3
    global e4
    global e5
    global e6
    top = Toplevel()
    top.title('域名反查机制')
    top.wm_attributes("-topmost", 1)
    top.geometry("400x550+550+250")
    top.resizable(width=False, height=False)
    L1 = ttk.Label(top, text="域名:", font=("宋体", 9))
    L1.place(relx=0.030, rely=0.060, relwidth=0.30, relheight=0.15)
    e1 = ttk.Entry(top)
    e1.place(relx=0.2, rely=0.10, relwidth=0.600, relheight=0.1)
    aim1 = urlparse(aim)
    e1.insert('0', aim1.netloc)
    L2 = ttk.Label(top, text="ip:", font=("宋体", 9))
    L2.place(relx=0.045, rely=0.3, relwidth=0.4, relheight=0.15)
    e2 = ttk.Entry(top)
    e2.place(relx=0.2, rely=0.30, relwidth=0.600, relheight=0.1)
    b = ttk.Button(top, text="查询", command=login_edu)
    b.place(relx=0.820, rely=0.120, relwidth=0.140, relheight=0.05)
    c = ttk.Button(top, text="查询", command=ip_C)
    c.place(relx=0.820, rely=0.330, relwidth=0.140, relheight=0.05)
    L3 = ttk.Label(top, text="ip whois:", font=("宋体", 9))
    L3.place(relx=0.045, rely=0.5, relwidth=0.4, relheight=0.15)
    e3 = ttk.Entry(top)
    e3.place(relx=0.2, rely=0.50, relwidth=0.600, relheight=0.1)

    e4 = ttk.Entry(top)
    e4.place(relx=0.2, rely=0.65, relwidth=0.600, relheight=0.07)

    L5 = ttk.Label(top, text="备案号:", font=("宋体", 9))
    L5.place(relx=0.025, rely=0.7, relwidth=0.17, relheight=0.15)
    e5 = ttk.Entry(top)
    e5.place(relx=0.2, rely=0.75, relwidth=0.600, relheight=0.07)

    L6 = ttk.Label(top, text="其他网站:", font=("宋体", 9))
    L6.place(relx=0.025, rely=0.8, relwidth=0.17, relheight=0.15)
    e6 = Text(top)
    e6.place(relx=0.2, rely=0.85, relwidth=0.600, relheight=0.12)
