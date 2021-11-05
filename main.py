from tkinter import *
import os
import platform
import nmap
import time
import multiprocessing
from  socket import *
import threading


def quickly_scanport():
    host = ip.get()
    service = {'21': 'FTP','22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS', '69': 'TFTP', '80': 'HTTP',
               '135': 'RPC', '137': 'NetBIOS', '139': 'Samba', '443': 'HTTPS', '1080': 'SOCKS', '1521': 'Oracle',
               '1433': 'SQL_Server','3306': 'MySQL', '3389': 'Remote_Destop', }
    top.text.insert(END,'Please waiting...\n')
    top.text.update()
    for p in service:
        try:
            tcpClisock = socket(AF_INET, SOCK_STREAM)
            tcpClisock.connect((host, int(p)))
            top.text.insert(END, "{0}:{1} -->oppend \n".format(service[p],p))
            top.text.update()
        except error:
            top.text.insert(END,"{0}:{1} -->not oppen \n".format(service[p],p))
            top.text.update()
        finally:
            tcpClisock.close()
            del tcpClisock


def qulickscan():
    qulickly_scan = threading.Thread(target=quickly_scanport,daemon=True)
    qulickly_scan.start()

def decide_server(host):
    # 获取操作系统
    sys = platform.system()
    # IP地址
    IP = host
    #top.text.insert(END,"{0} \n".format(sys))
    if sys == "Windows":
        # 打开一个管道ping IP地址
        visit_IP = os.popen('ping %s' % IP)
        # 读取结果
        result = visit_IP.read()
        # 关闭os.popen()
        visit_IP.close()
        # 判断IP是否在线
        if 'TTL' in result:
            top.text.insert(END,'{0} is online \n'.format(IP))
            top.text.update()
        else:
            top.text.insert(END,'{0} is not online \n'.format(IP))
            top.text.update()
    elif sys == "Linux":
        visit_IP = os.popen('ping -c 1 %s' % IP)
        result = visit_IP.read()
        visit_IP.close()
        if 'ttl' in result:
            top.text.insert(END,'{0} is online \n'.format(IP))
            top.text.update()
        else:
            top.text.insert(END,'{0} is not online \n'.format(IP))
            top.text.update()
    else:
        top.text.insert(END,"Error \n")
        top.text.update()


def _quit():
    top.quit()
    top.destroy()
    exit()


def scan_port(host,port):
    nm = nmap.PortScanner()
    try:
        result = nm.scan(host, str(port))
        state = result['scan'][host]['tcp'][port]['state']
        top.text.insert(END, "{0} port state: {1} \n".format(port, state))
        top.text.update()
    except Exception as e:
        #time.sleep(5)
        top.text.insert(END, 'Scan Error! {0}\n'.format(e))
        top.text.update()


def scanport():
    host = ip.get()
    if len(host) ==0:
        top.text.insert(END, 'ERROR! Host is empty! \n')
        top.text.update()
        return
    decideserver = threading.Thread(target=decide_server,args=(host,),daemon=True)
    decideserver.start()
    portstart = port_start.get()
    portend = port_end.get()
    top.text.insert(END,"Scanning {0},port:{1} to {2},please wait…… \n".format(host,portstart,portend))
    top.text.update()
    for port in range(portstart, portend):
        scan_port_thread = threading.Thread(target=scan_port,args=(host,port),daemon=True)
        scan_port_thread.start()

    top.text.insert(END, 'Scan complete ! \n')
    top.text.update()


top = Tk()
top.title("Security tools")
top.geometry('800x500')

top.label = Label(top,text = "Security Tools").place(x=160,y=15)
top.rbtn = Radiobutton(top,text = "已连接",fg='green').place(x=0,y=0)
top.label_ip = Label(top,text = "Enter IP:").place(x=90,y=45)
ip = StringVar()
port_start = IntVar()
port_end = IntVar()
top.entry = Entry(top,textvariable = ip).place(x=145,y=45)
top.label_ip = Label(top,text = "Enter Port:").place(x=90,y=75)
top.entry = Entry(top,textvariable = port_start,width=8).place(x=160,y=75)
top.label_ip = Label(top,text = "to",width=2).place(x=205,y=75)
top.entry = Entry(top,textvariable = port_end,width=8).place(x=225,y=75)
top.scan_port = Button(top,text = "Scan",command=scanport).place(x=150,y=105)
top.scan_port = Button(top,text = "Quickly Scan",command=qulickscan).place(x=200,y=105)
top.label_ip = Label(top,text = "Consel").place(x=540,y=15)
top.text = Text(top,height=34,width=60,bg="white")
top.text.place(x=350,y=40)

top.mainloop()