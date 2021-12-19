import os
from tkinter import Toplevel, ttk, filedialog


# def webcrack_ui():
#     global e1
#     global top
#     top = Toplevel()
#     top.title('webcrack')
#     top.wm_attributes("-topmost",1)
#     top.geometry("400x100+550+250")
#     top.resizable(width=False, height=False)
#     L1=ttk.Label(top,text="上传文件:",font=("宋体",9))
#     L1.place(relx = 0.020,rely =0.180,relwidth =0.30,relheight = 0.30)
#     e1=ttk.Entry(top)
#     e1.place(relx = 0.2,rely =0.25,relwidth = 0.600,relheight = 0.25)
#     c=ttk.Button(top,text="上传",command=webcrack_file)
#     c.place(relx = 0.840,rely =0.22,relwidth = 0.140,relheight = 0.27)
#
#
# def webcrack_file():
#     e1.delete(0, 'end')
#     filePath=filedialog.askopenfilename()
#     e1.insert("end",filePath+'\n')
#     webcrack_execution()
#
# def webcrack_execution():
#     cmd="start "+"python"+" Plugins/WebCrack/webcrack.py -f {}".format(e1.get().strip())
#     os.system(cmd)

def webcrack_ui():
    cmd = "start " + "python" + " Plugins/WebCrack/webcrack.py"
    os.system(cmd)