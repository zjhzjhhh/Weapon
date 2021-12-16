import os
from tkinter import messagebox, ttk

import pyperclip




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




# def new_num():
#     global num
#     num = 1