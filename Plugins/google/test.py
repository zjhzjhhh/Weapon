# # coding:utf-8
# import tkinter as tk
# from tkinter import *
#
#
# root = tk.Tk()
# root.title('Test')
# e = StringVar()
#
#
# def callback():
#     # tkMessageBox.showinfo('title','hello world')
#     entry = Entry(root, textvariable=e)
#     e.set('请输入')
#     entry.pack()
#
#
# def bnt():
#     Button(root, text='确认使用', fg='red', bd=2, width=28,
#            command=callback).pack()
#     root.withdraw()
#
#
# bnt()
# root.mainloop()