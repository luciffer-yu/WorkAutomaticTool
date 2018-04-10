#-*- coding: utf-8 -*-
import urllib2
import xlwt
import ssl
import sys
from bs4 import BeautifulSoup
from selenium import webdriver
import GlobalVar

ssl._create_default_https_context = ssl._create_unverified_context

class DiscoverVul:
    def __init__(self, ip, account, date_range, driver_path, vul_path):
        self.ip = ip
        self.account = account
        self.rdate = date_range
        self.driver = driver_path
        self.data_path = vul_path
        self.token = ''
        self.sessionid = ''
        self.vulid = []
        self.vul_data = []

    def discover_start(self):
        self.__login()
        print GlobalVar.time_stamp() + 'Start gathering vulnerability between %s and %s' % (self.rdate[0], self.rdate[1])
        category = self.__step_1()
        if category == '':
            print 'Not found any vulner'
            return
        for x in category:
            data = self.__step_2(x)
            for y in data:
                plantform = y.find_next('a').get_text()
                if int(plantform.split('[')[1][0]) != 0:
                    self.__step_3(y['id'])
        for id in self.vulid:
            d = self.__query_vulid(id)
            self.vul_data.append(d)
            print "\rFound CVE: %s" % d[2],
            sys.stdout.flush()
        print '\n'
        print GlobalVar.time_stamp() + 'Gather vulnerability data end, totally %d entries have been got' % len(self.vul_data)
        return self.vul_data

    def save_vul_data(self):
        book = xlwt.Workbook()
        sheet = book.add_sheet('data', cell_overwrite_ok=False)
        sheet.write(0, 0, u'漏洞名称')
        sheet.write(0, 1, u'漏洞等级')
        sheet.write(0, 2, u'CVE编号')
        sheet.write(0, 3, u'漏洞详情')
        sheet.write(0, 4, u'解决方法')
        sheet.write(0, 5, u'发现日期')
        row = 0
        for data in self.vul_data:
            row += 1
            sheet.write(row, 0, data[0])
            sheet.write(row, 1, data[1])
            sheet.write(row, 2, data[2])
            sheet.write(row, 3, data[3])
            sheet.write(row, 4, data[4])
            sheet.write(row, 5, data[5])
        book.save(self.data_path)
        print 'Data has been save in path %s' % self.data_path

    def __step_1(self):
        category = []
        url = "https://" + self.ip + "/template/getTreeHtml?val=System&conditions=date_found_start=" + self.rdate[0] + ",date_found_end=" + self.rdate[1] + "&op_type=addUtemp&temp_id=&"
        header = {"Cookie": "csrftoken=" + self.token + ";" + "left_menustatue_NSFOCUSRSAS=3|0|https://" + self.ip + "/template/index/" + ";" + "sessionid=" + self.sessionid,
                  "Referer": "https://" + self.ip + "/template/add_template/?op_type=addUtemp&",
                  "X-Requested-With": "XMLHttpRequest",
                  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
                  "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
                  }
        req = urllib2.Request(url, headers=header)
        page = urllib2.urlopen(req).read()
        soup = BeautifulSoup(page, 'html.parser')
        data = soup.find_all('div')
        for item in data:
            plantform = item.find_next('a').get_text()
            if int(plantform.split('[')[1][0]) != 0:
                category.append(item['id'])
        if len(category) == 0:
            return ''
        return category

    def __step_2(self, category):
        url = "https://" + self.ip + "/template/getTreeHtml?val=System&conditions=date_found_start=" + self.rdate[0] + ",date_found_end=" + self.rdate[1] + "&op_type=addUtemp&temp_id=&&id=" + category + "&offset=0&limit=3"
        header = {"Cookie": "csrftoken=" + self.token + ";" + "left_menustatue_NSFOCUSRSAS=3|0|https://" + self.ip + "/template/index/" + ";" + "sessionid=" + self.sessionid,
                  "Referer": "https://" + self.ip + "/template/add_template/?op_type=addUtemp&",
                  "X-Requested-With": "XMLHttpRequest",
                  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
                  "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
                  }
        req = urllib2.Request(url, headers=header)
        page = urllib2.urlopen(req).read()
        soup = BeautifulSoup(page, 'html.parser')
        data = soup.find_all('div')
        return data

    def __step_3(self, category):
        url = "https://" + self.ip + "/template/getTreeHtml?val=System&conditions=date_found_start=" + self.rdate[0] + ",date_found_end=" + self.rdate[1] + "&op_type=addUtemp&temp_id=&&id=" + category + "&offset=0&limit=2"
        header = {"Cookie": "csrftoken=" + self.token + ";" + "left_menustatue_NSFOCUSRSAS=0|0|https://" + self.ip + "/dashboard/show/" + ";" + "sessionid=" + self.sessionid,
                  "Referer": "https://" + self.ip + "/template/add_template/?op_type=addUtemp&",
                  "X-Requested-With": "XMLHttpRequest",
                  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
                  "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
                  }
        req = urllib2.Request(url, headers=header)
        page = urllib2.urlopen(req).read()
        soup = BeautifulSoup(page, 'html.parser')
        data = soup.find_all('div')
        for item in data:
            if item['id'].find('no data') >= 0:
                continue
            if item['id'] not in self.vulid and item['id'] != '':
                self.vulid.append(item['id'])

    def __query_vulid(self, id):
        vul = ''
        cve = ''
        detail = ''
        handle = ''
        level = ''
        date = ''

        url = 'https://' + self.ip + '/template/show_vul_desc?id=' + id
        header = {"Cookie": "csrftoken=" + self.token + ";" + "left_menustatue_NSFOCUSRSAS=0|0|https://" + self.ip + "/dashboard/show/" + ";" + "sessionid=" + self.sessionid,
                  "Referer": "https://" + self.ip,
                  "X-Requested-With": "XMLHttpRequest",
                  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
                  "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                  "Upgrade-Insecure-Requests": 1
                  }

        req = urllib2.Request(url, headers=header)
        page = urllib2.urlopen(req, context=ssl._create_unverified_context()).read()
        soup = BeautifulSoup(page, 'html.parser')
        vul_table = soup.find_all('th')
        for item in vul_table:
            if item.string == u'漏洞名称':
                if item.next_sibling.next_sibling.find_next('img')['src'].find('high') >= 0:
                    level = u'高'
                elif item.next_sibling.next_sibling.find_next('img')['src'].find('middle') >= 0:
                    level = u'中'
                elif item.next_sibling.next_sibling.find_next('img')['src'].find('low') >= 0:
                    level = u'低'
                vul = item.next_sibling.next_sibling.get_text()
            if item.string == u'漏洞描述':
                detail = item.next_sibling.next_sibling.get_text()
            if item.string == u'解决方法':
                handle = item.next_sibling.next_sibling.get_text()
            if item.string == u'CVE编号':
                cve = item.next_sibling.next_sibling.get_text()
            if item.string == u'发现日期':
                date = item.next_sibling.next_sibling.get_text()

        return (vul, level, cve, detail, handle, date)

    def __login(self):
        print GlobalVar.time_stamp() + 'Login RSAS: ' + self.ip
        driver = webdriver.Chrome(executable_path=self.driver)
        driver.get("https:" + self.ip + "/accounts/login_view/")
        elem_user = driver.find_element_by_name("username")
        elem_user.send_keys(self.account.split(',')[0])
        elem_pwd = driver.find_element_by_name("password")
        elem_pwd.send_keys(self.account.split(',')[1])
        driver.find_element_by_class_name("submit").click()
        cookie = driver.get_cookies()
        self.token = cookie[0]['value']
        self.sessionid = cookie[1]['value']
        print GlobalVar.time_stamp() +  'Login RSAS Complete'
