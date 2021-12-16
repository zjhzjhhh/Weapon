import requests
from lxml import etree
from tkinter import Toplevel, ttk


def IP138_search():
    global e1
    global e2
    top = Toplevel()
    top.title('ip138')
    top.wm_attributes("-topmost", 1)
    top.geometry("400x150+550+250")
    top.resizable(width=False, height=False)
    L1 = ttk.Label(top, text="IP", font=("宋体", 9))
    L1.place(relx=0.020, rely=0.030, relwidth=0.30, relheight=0.30)
    e1 = ttk.Entry(top)
    e1.place(relx=0.2, rely=0.10, relwidth=0.600, relheight=0.2)
    L2 = ttk.Label(top, text="结果:", font=("宋体", 9))
    L2.place(relx=0.095, rely=0.4, relwidth=0.3, relheight=0.30)
    e2 = ttk.Entry(top)
    e2.place(relx=0.2, rely=0.40, relwidth=0.600, relheight=0.4)
    b = ttk.Button(top, text="查询", command=ip_information)
    b.place(relx=0.820, rely=0.090, relwidth=0.140, relheight=0.20)


def ip_information():
    e2.delete(0, 'end')
    base_url2 = "https://m.ip138.com/iplookup.asp?ip="
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
    }
    name = e1.get()
    requests_url = base_url2 + name
    response2 = requests.get(url=requests_url, headers=headers).content
    source2 = etree.HTML(response2)
    infomation = source2.xpath('//tr[@class="active"]/td/text()')
    e2.insert("end", str(infomation[1]) + '\n')