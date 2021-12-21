# #coding=utf-8
# import configparser
# import os
#
#
# def Xrun(filename):
#     cf = configparser.ConfigParser()
#     cf.read("./config/conf.ini")
#     #prog = cf.get("xray", "program")
#     ip = cf.get("xray", "IP")
#     port = cf.get("xray", "PORT")
#     cmd = "./Plugins/Xray/xray_windows_amd64.exe webscan --listen {}:{} --html-output {}.html".format(ip,port,filename)
#     os.system(cmd)
