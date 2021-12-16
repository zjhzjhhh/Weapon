import configparser
from tkinter import ttk

import tkinter as tk

from ttkthemes import ThemedTk


def Search_ui():

    proxies = {'http': None, 'https': None}
    cf = configparser.ConfigParser()
    cf.read("./config/config.ini")
    fofa_email = cf.get('fofa api', 'EMAIL')
    fofa_key = cf.get('fofa api', 'KEY')

    window = tk.Tk()
    window.withdraw()
    window = ThemedTk(theme="arc", toplevel=True, themebg=True)
    window.title('NetworkSecurity pro+ https://github.com/YanMu2020[Windows试验版]')
    window.geometry("1320x700+350+150")
    menbar = tk.Menu(window, tearoff=0)
    menbar.add_command(label='ICON')
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

    h1 = tk.IntVar()
    Checkbutton_1 = ttk.Checkbutton(window, text="fofa", variable=h1, offvalue=0)#, command=sr
    Checkbutton_1.place(relx=0.340, rely=0.289, relwidth=0.090, relheight=0.040)

    window.mainloop()

if __name__ == '__main__':
    Search_ui()

