# _*_ coding:utf-8 _*_
import requests, time, openpyxl, re, argparse, sys, sqlite3,ast,json
from multiprocessing import Pool, Manager
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def readfie(txt):
    txt_list = []
    with open(txt, 'r', encoding="utf-8") as f1:
        for line in f1.readlines():
            if line.startswith(u"\ufeff"):
                line = line.encode("utf8")[3:].decode("utf8")
            if '    ' in line or '\n' in line:
                line = line[:-1]
            txt_list.append(line)
    return txt_list


def writetite():
    local_time = time.strftime('%Y_%m_%d_%H_%M_%S', time.localtime(time.time()))
    # 创建结果文件
    filename = "vuldir" + local_time + ".xlsx"
    wb = openpyxl.Workbook()
    ws = wb.create_sheet(index=0)
    title_list = ['id', 'cms', 'baseurl', 'vulurl', 'finger', 'msg']
    ws.append(title_list)
    wb.save(filename)
    return filename


def gethttp(url1, tmpcontent):
    res_list = []
    # 取字典中的flag，状态码为404的白名单列表，便于某些漏洞的检查
    ext404 = ["用友 ERP-NC NCFindWeb 目录遍历漏洞", "用友 NC NCFindWeb 任意文件读取漏洞"]
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36',
        'Content-Encoding': 'deflate',
        'Content-Disposition': 'attachment; filename="filename.jpg"'
    }
    try:
        res_ori = requests.get(url1, headers=header, verify=False, allow_redirects=True, timeout=3)
        restxtori = res_ori.text
    except:
        pass
    else:
        for tmp1 in tmpcontent:
            finger = ast.literal_eval(tmp1[4])
            if finger:
                for ftmp in finger:
                    if ftmp in restxtori:
                        id = tmp1[0]
                        cms = tmp1[1]
                        baseurl = tmp1[2]
                        vulurl1 = tmp1[3]
                        msgtrue = ast.literal_eval(tmp1[5])
                        msgfalse = tmp1[6]
                        flag = tmp1[7]
                        switchtmp = tmp1[8]
                        switch_msgtrue = json.loads(switchtmp)['msgtrue']
                        url = url1 + baseurl
                        vulurl = url1 + vulurl1
                        try:
                            res = requests.get(url, headers=header, verify=False, allow_redirects=False, timeout=5)
                            status = res.status_code
                            restxt = res.text
                        except:
                            pass
                        else:
                            if flag in ext404:
                                status = 200  # 假的200，这里也必定存在很多误报
                            if msgtrue:
                                # 与关系
                                if switch_msgtrue == 'true':
                                    if all(mttmp in restxt for mttmp in msgtrue):
                                        res_list.append([id, cms, url, vulurl, str(finger), "存在" + flag])
                                        print(url + "  |  " + "存在 " + flag)
                                        # break
                                # 或关系
                                elif switch_msgtrue == 'false':
                                    for mttmp in msgtrue:
                                        if mttmp in restxt:
                                            res_list.append([id, cms, url, vulurl, str(finger), "存在" + flag])
                                            print(url + "  |  " + "存在 " + flag)
                                        # break
                                    # break
                            elif msgfalse:
                                if msgfalse in restxt:
                                    res_list.append([id, cms, url, vulurl, str(finger), "不存在" + flag])
                                    print(url + "  |  " + "不存在" + flag)
                                    # break
                            elif status not in [301, 302, 403, 404]:
                                res_list.append([id, cms, url, vulurl, str(ftmp), "指纹匹配，可能存在" + flag])
                                print(url + "  |  " + "指纹匹配，可能存在" + flag)
                                # break
                    break
        return res_list


def readdb(queue, bigtype, smalltype, filename):
    res_list = []
    url = queue.get()
    tmpdb = sqlite3.connect("vuldir.db")
    cursor = tmpdb.cursor()
    if bigtype == "all":
        # 查表名
        cursor.execute("select name from sqlite_master where type='table';")
        tables = cursor.fetchall()
        for tmpt in tables:
            if 'sqlite' not in tmpt[0]:
                try:
                    # 查表内内容
                    cursor.execute("select * from " + tmpt[0] + ";")
                    tmpcontent = cursor.fetchall()
                except Exception as bb:
                    # print(bb)
                    pass
                else:
                    res_list1 = gethttp(url, tmpcontent)
                    res_list.extend(res_list1)
    else:
        table = bigtype
        if smalltype == "all":
            cursor.execute("select * from " + table + ";")
            tmpcontent = cursor.fetchall()
        else:
            try:
                cursor.execute("select * from " + table + " where cms='" + smalltype + "';")
                tmpcontent = cursor.fetchall()
            except Exception as aa:
                # print(aa)
                pass
        res_list = gethttp(url, tmpcontent)
    return res_list, filename


# 回调函数将结果写入文件
def output(res_list2):
    res_list1, filename = res_list2
    if res_list1:
        # 每条结果时打开该结果文件并写入
        wb = openpyxl.load_workbook(filename)
        for listtmp in res_list1:
            sheetnames = wb.sheetnames
            ws = wb[sheetnames[0]]
            ws = wb.active
            ws.append(listtmp)
            wb.save(filename)


def selectdb_big():
    bigtype_list = []
    tmpdb = sqlite3.connect("vuldir.db")
    cursor = tmpdb.cursor()
    # 查表名
    cursor.execute("select name from sqlite_master where type='table';")
    tables = cursor.fetchall()
    for tmpt in tables:
        if 'sqlite' not in tmpt[0]:
            bigtype_list.append(tmpt[0])
    return bigtype_list


def selectdb_small(bigtype):
    smalltype_list = []
    tmpdb = sqlite3.connect("vuldir.db")
    cursor = tmpdb.cursor()
    cursor.execute("select * from " + bigtype + ";")
    tmpcontent = cursor.fetchall()
    for tmp1 in tmpcontent:
        smalltype_list.append(tmp1[1])
    smalltype_list = list(set(smalltype_list))
    return smalltype_list


def pool(url_list, thread, bigtype, smalltype, filename):
    # 多进程开始
    pool = Pool(thread)
    queue = Manager().Queue()
    if "str" in str(type(url_list)):
        url1 = re.findall('(.*[0-9]+)/', url_list)
        if not url1:
            url1 = url_list
        else:
            url1 = url1[0]
        queue.put(url1)
        pool.apply_async(func=readdb, args=(queue, bigtype, smalltype, filename,), callback=output)
    elif "list" in str(type(url_list)):
        for url in url_list:
            url1 = re.findall('(.*:[0-9]+)/', url)
            if not url1:
                url1 = url
            else:
                url1 = url1[0]
            queue.put(url1)
            pool.apply_async(func=readdb, args=(queue, bigtype, smalltype, filename,), callback=output)
    pool.close()
    pool.join()


def help():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', '-u', help='单个URL')
    parser.add_argument('--urlfile', '-uf', help='URL文件')
    parser.add_argument('--thread', '-t', help='进程数,默认30')
    parser.add_argument('--biglist', '-bl', help='大分类漏洞方向列表', action="store_true")
    parser.add_argument('--smalltlist', '-sl', help='某大分类下细分漏洞方向列表', action="store_true")
    parser.add_argument('--bigtype', '-bt', help='选择某大分类的漏洞方向')
    parser.add_argument('--smalltype', '-st', help='选择小分类的漏洞方向')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = help()
    if args.bigtype:
        bigtype = args.bigtype
        if args.smalltype:
            smalltype = args.smalltype
        else:
            smalltype = "all"
    else:
        bigtype = "all"
        smalltype = "all"
    if args.biglist:
        bigtype = selectdb_big()
        print("目前漏洞方向有: " + str(bigtype))
    if args.smalltlist:
        smalltype = selectdb_small(bigtype)
        print("指定大类的细分漏洞方向有: " + str(smalltype))
    if args.thread:
        thread = int(args.thread)
    else:
        thread = 1
    if args.url:
        urls = args.url
    elif args.urlfile:
        urls = readfie(args.urlfile)
    else:
        sys.exit(0)
    filename = writetite()
    pool(urls, thread, bigtype, smalltype, filename)
