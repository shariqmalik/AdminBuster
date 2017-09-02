#!/usr/bin/python
import sys
import requests
import httplib
import time
import json
import re
import socket
from os import name, system
from datetime import datetime
from Queue import Queue
from threading import Thread, ThreadError

system('cls') if name == 'nt' else system('clear')
# Global Variables
ua = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'}
panels = ["/admin/", "/administrator/", "/webadmin/", "/control/", "/admincp/"]
export_results = []

q = Queue()

# Lets start :D


def banner():
    print('''
  ___      _           _      ______           _            
 / _ \    | |         (_)     | ___ \         | |           
/ /_\ \ __| |_ __ ___  _ _ __ | |_/ /_   _ ___| |_ ___ _ __ 
|  _  |/ _` | '_ ` _ \| | '_ \| ___ \ | | / __| __/ _ \ '__|
| | | | (_| | | | | | | | | | | |_/ / |_| \__ \ ||  __/ |   
\_| |_/\__,_|_| |_| |_|_|_| |_\____/ \__,_|___/\__\___|_|   
                                                            
                                                ~by Shariq Malik
    ''')


class counter:
    count = 0

class output:
    'class to export output to html'

    file = open("buster-output.html", 'a')

    def __init__(self, target, scanner):
        header = "<br/><font face=monospace color=red>Results For <font color=Blue>'%s'</font><br/>Report Time: <font color=blue>%s</font><br/>Reverse Lookup: <font color=blue>%s</font></font><br/>" % (
            target, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), scanner)
        output.file.write(header)

    def data(self, link, respcode, wp):
        out = '<font face=monospace>[%s] <a href="%s" target="_blank">%s %s</a></font><br/>' % (
            respcode, link, link, wp)
        output.file.write(out)

    def close(self):
        output.file.close()


def urlfix(url):
    'Url Fixer'
    url = url[:url.rindex('/')] if '/' in url[-1] else url
    return url.replace('https://', '').replace('http://', '').replace('/', '')


def exportData(target, scanner):
    'Function for Generating Output'

    export = output(target, scanner)
    for data in export_results:
        export.data(*data)

    export.close()


def yougetsignal(target):
    'Function for Reverse Domain Lookup (YouGetSignal)'

    url = "http://domains.yougetsignal.com/domains.php"
    postdata = {'remoteAddress': target, 'key': ''}
    r = requests.post(url, params=postdata, headers=ua,
                      timeout=timeOut, proxies=px)
    resp = json.loads(r.text)
    results = [i[0] for i in resp['domainArray']]

    QueueFiller(results)

    return [r.status_code, resp['domainCount']]


def hackertarget(target):
    'Function for Reverse Domain Lookup (HackerTarget)'

    api = "http://api.hackertarget.com/reverseiplookup/?q=%s" %target
    request = requests.get(api, headers=ua, timeout=timeOut, proxies=px)
    results = request.text.split('\n')
    QueueFiller(results)

    return [request.status_code, len(results)]


def ViewDns(target):
    'Function for Reverse Domain Lookup (ViewDNS)'

    url = "http://viewdns.info/reverseip/?t=1&host=%s" %target
    request = requests.get(url, headers=ua, timeout=timeOut, proxies=px)
    data = request.text
    results = re.findall('<td>(.+?\..+?)</td>', data)
    del results[0], results[0], results[0]
    QueueFiller(results)

    return [request.status_code, len(results)]

def ViewDnsApi(target,Key):
    'Function for Reverse Domain Lookup (View DNS Using API)'
    url = "https://api.viewdns.info/reverseip/?host=%s&apikey=%s&output=json" %(target,Key)
    request = requests.get(url, headers=ua, timeout=timeOut, proxies=px)
    data = json.loads(request.text)
    results = [i['name'] for i in data['response']['domains']]
    QueueFiller(results)

    return [request.status_code,data['response']['domain_count']]


def QueueFiller(urls):
    'Fill up the Queue'

    for link in urls:
        q.put('http://' + link)
    return None


def CheckAdmin(queue):
    'Function Checking Admin Panels'

    while not queue.empty():
        try:
            counter.count += 1
            sys.stdout.write("Checked '%i' and Remaining '%i'..%s\r" % (
                counter.count, len(queue.queue) - 1, ' ' * 8))
            sys.stdout.flush()
            getlink = queue.get(False)
            for adm in panels:
                newlink = getlink + adm
                try:
                    # Code Garbage but it works :D
                    admReq = requests.get(
                        newlink, headers=ua, timeout=timeOut, proxies=px)
                    if admReq.status_code != 404 and ('type=' and 'password') in admReq.text:
                        print("[%s] %s: %s %s    " % (admReq.status_code, httplib.responses[admReq.status_code],
                                                   newlink, ['', "'WordPress'"]['wp-admin' in admReq.headers['Set-Cookie']]))
                        export_results.append([newlink, admReq.status_code, [
                                              '', "'WordPress'"]['wp-admin' in admReq.headers['Set-Cookie']]])
                        break

                except KeyboardInterrupt:
                    print("-" * 35)
                    print("\n[*]User Interrupted!")
                    return None
                except:
                    pass

        except KeyboardInterrupt:
            print("-" * 35)
            print("\n[*]User Interrupted!")
            return None
        except Exception, e:
            print("\nError: %s" % e)
            return None
    queue.task_done()


def action(target, ConnPerSec, lookup,key=None):
    'Function Performing Action Task'
    target_ip = socket.gethostbyname(target)
    if lookup == 1:
        Response = yougetsignal(target_ip)
        scanner = "YouGetSignal"
    elif lookup == 2:
        Response = hackertarget(target_ip)
        scanner = "HackerTarget"
    elif lookup == 3:
        Response = ViewDns(target_ip)
        scanner = "ViewDNS"
    elif lookup == 4:
        Response = ViewDnsApi(target_ip,key)
        scanner = "ViewDNS (Using API)"

    ServerStatus = Response[0]
    Domains = Response[1]

    print("-" * 35)
    print("Server Status  : %s" % httplib.responses[ServerStatus])
    print("Target IP Addr : %s" % (target_ip))
    print("Scanning using : %s" % scanner)
    print("Total Domains  : %s" % Domains)
    print("No of Threads  : %s" % ConnPerSec)
    print("Timeout Sec    : %s sec" % timeOut)
    print("Proxy Enabled  : %s" % ('Yes' if px else 'No'))
    print("-" * 35)
    # Threading :D
    if ConnPerSec > 0:
        try:
            for i in xrange(ConnPerSec):
                t = Thread(target=CheckAdmin, args=(q,))
                t.daemon = True
                t.start()
            t.join()
        except KeyboardInterrupt:
            print("-" * 35)
            print("[+]Output saved to 'buster-output.html'")
            print("\n[*]User Interrupted!")
            return None
    else:
        # Non Threaded :(
        CheckAdmin(q)

    exportData(target, scanner)


def Main():
    'Main Shit'

    banner()
    try:
        global px, timeOut
        site = raw_input("Enter Site: ")
        site = urlfix(site)
        # Check for Custom options :D
        if (raw_input("Do you want custom options ('N' for default options) [Y/N]:").lower() == 'y'):
            threads = int(input("No Of Threads (0 for non-thread mod): "))
            timeOut = int(input("Timeout Seconds: "))
            lookup = int(
                input("1. yougetsignal\n2. hackertarget\n3. View Dns\n4. View Dns (Using API)\n> "))
            if lookup == 4:
                ApiKey = raw_input("Enter Your Api Key: ")
            else:
                ApiKey = None
            # proxy input
            if (raw_input("Do you want to use proxy? [Y/N]: ").lower() == 'y'):
                if (raw_input("Want to use TOR? [Y/N]: ").lower() == 'y'):
                    Px_proto = 'http'
                    Px_ip = 'socks5://127.0.0.1'
                    Px_port = 9050
                else:
                    Px_proto = raw_input("Proxy Protocol: ")
                    Px_ip = raw_input("Proxy ip: ")
                    Px_port = int(input("Proxy Port: "))

                px = {
                    Px_proto: "%s:%s" % (Px_ip, Px_port)
                }
            else:
                px = {}

        # Default Values (Modify Them as you need)
        else:
            threads = 2
            lookup = 1
            timeOut = 2
            px = {}

        t1 = time.time()  # startTime
        action(site, threads, lookup, ApiKey)
        t2 = time.time()  # endTime

        print('Task Complete..%s' % (' ' * 18))
        print("\n[-]Total Found : %s" % len(export_results))
        print("[+]Output saved to 'buster-output.html'")
        sys.exit("[+]Program Exited in '%s'" %
                 time.strftime("%M min and %S sec", time.gmtime(t2 - t1)))
    except KeyboardInterrupt:
        print("-" * 35)
        t2 = time.time()
        print("\n[*]User Interrupted!")
        print("[-]Total Found : %s" % len(export_results))
        print("[+]Output saved to 'buster-output.html'")
        sys.exit("[+]Program Exited in '%s'" %
                 time.strftime("%M min and %S sec", time.gmtime(t2 - t1)))

    except Exception, e:
        t2 = time.time()
        print("\nError: %s" % e)
        sys.exit("[+]Program Exited in '%s'" %
                 time.strftime("%M min and %S sec", time.gmtime(t2 - t1)))


if __name__ == '__main__':
    Main()
