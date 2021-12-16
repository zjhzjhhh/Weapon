import base64
from tkinter import Toplevel, ttk

import mmh3
import requests


def create():
    global e1
    global e2
    top = Toplevel()
    top.title('ICON')
    top.wm_attributes("-topmost", 1)
    top.geometry("400x150+550+250")
    top.resizable(width=False, height=False)
    L1 = ttk.Label(top, text="ICON地址:", font=("宋体", 9))
    L1.place(relx=0.020, rely=0.030, relwidth=0.30, relheight=0.30)
    e1 = ttk.Entry(top)
    e1.place(relx=0.2, rely=0.10, relwidth=0.600, relheight=0.2)
    L2 = ttk.Label(top, text="结果:", font=("宋体", 9))
    L2.place(relx=0.095, rely=0.4, relwidth=0.3, relheight=0.30)
    e2 = ttk.Entry(top)
    e2.place(relx=0.2, rely=0.40, relwidth=0.600, relheight=0.4)
    b = ttk.Button(top, text="转换", command=hash)
    b.place(relx=0.820, rely=0.090, relwidth=0.140, relheight=0.20)


def hash():
    e2.delete(0, 'end')
    url = e1.get()
    r = requests.get(url, verify=False)
    favicon = base64.encodebytes(r.content)
    hash = mmh3.hash(favicon)
    result = 'icon_hash="{}"'.format(hash)
    e2.insert("end", result + '\n')