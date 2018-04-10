#-*- coding: utf-8 -*-
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By

class suse_analyze():
    def __init__(self, suse_key, task, driver):
        self.task = task
        index = task.rindex('/')
        self.cveid = task[index + 1:len(task)]
        self.result = {}
        self.result[self.cveid] = []
        self.suse_key = suse_key
        self.driver = driver

    def start_analyze(self):
        return self.__send_request2suse()

    def __send_request2suse(self):
        page = self.driver.explicit_get_page_source(self.task, (By.LINK_TEXT, 'SUSE Linux security updates'))
        if page == '':
            return self.result
        else:
            return self.__suse_page_analyze(page)

    def __suse_page_analyze(self, page):
        soup = BeautifulSoup(page, 'html.parser')

        info = soup.find_all('h3', string='SUSE information', limit=1)
        if info:
            str = info[0].next_element.next_element.next_element.string.strip()
            if str.find('not affect SUSE products') >= 0:
                for key in self.suse_key:
                    self.result[self.cveid].append((key, 'Not affected'))

        release = soup.find_all('h3', string='List of released packages', limit=1)

        if release:
            for item1 in release[0].next_element.next_element.next_element.next_element.next_element:
                try:
                    for child in item1.descendants:
                        for key in self.suse_key:
                            if child.find(key) >= 0:
                                code = child.find_next('code')
                                self.result[self.cveid].append((key,code.string.strip()))
                                break
                except Exception,e:
                    continue

            state = soup.find_all('h3', string='Status of this issue by product and package', limit=1)
            if state:
                s_table = state[0].find_next('table')
                for x in s_table.children:
                    if len(x) != 1:
                        product = x.find_next('td')
                        for key in self.suse_key:
                            if product.string.strip().find(key) >= 0:
                                s = product.next_sibling.next_sibling.next_sibling.next_sibling.string.strip()
                                if s.find('Not affected') >= 0 :
                                    self.result[self.cveid].append((key,'Not affected'))
                                break
        return self.result

class redhat_analyze():
    def __init__(self, redhat_key, task, driver):
        self.task = task
        index = task.rindex('/')
        self.cveid = task[index + 1:len(task)]
        self.result = {}
        self.result[self.cveid] = []
        self.redhat_key = redhat_key
        self.driver = driver

    def start_analyze(self):
        return self.__send_request2redhat()

    def __send_request2redhat(self):
        page = self.driver.explicit_get_page_source(self.task, (By.LINK_TEXT, 'Red Hat Product Security'))
        if page == '':
            return self.result
        else:
            return self.__redhat_page_analyze(page)

    def __redhat_refer_page_analyze(self, url, key):
        page = self.driver.implicit_get_page_source(url)
        soup = BeautifulSoup(page, 'html.parser')
        res = soup.find_all('h2', string = 'Red Hat Enterprise Linux Server '+ key[-1], limit=1)
        if res:
            arch = res[0].find_next('th', string='x86_64')
            ver = arch.find_next('td').get_text().strip()
            if ver:
                value = ver.split('.')
                map(lambda x: value.pop(), [x for x in range(3)])
                #print '.'.join(value)
                return '.'.join(value)
        return ''

    def __redhat_page_analyze(self, page):
        soup = BeautifulSoup(page, 'html.parser')
        tables = soup.find_all('table',
                               attrs={'class': 'table feature-table', 'xmlns:xs': 'http://www.w3.org/2001/XMLSchema'})
        if tables:
            for table in tables:
                for child in table.descendants:
                    for key in self.redhat_key:
                        if child.find(key) >= 0:
                            if child.parent.next_sibling.next_sibling.get_text().find('RHSA') >= 0:
                                version = self.__redhat_refer_page_analyze(child.parent.next_sibling.next_sibling.a['href'], key)
                                if version:
                                    self.result[self.cveid].append((key, version))
                                continue
                            if child.find_next('td', string='Will not fix'):
                                node = child.find_next('td', string='Will not fix')
                                not_fix = node.find_previous_sibling('th', attrs={'headers':'th-platform'}).string
                                if not_fix:
                                    try:
                                        if int(not_fix[-1]) == int(key[-1]):
                                            #return 'Will not fix'
                                            self.result[self.cveid].append((key, 'Will not fix'))
                                            continue
                                    except:
                                        pass
                            if child.find_next('td', string='Not affected'):
                                node = child.find_next('td', string='Not affected')
                                not_affect = node.find_previous_sibling('th', attrs={'headers':'th-platform'}).string
                                if not_affect:
                                    try:
                                        if int(not_affect[-1]) == int(key[-1]):
                                            self.result[self.cveid].append((key, 'Not affected'))
                                            continue
                                    except:
                                        pass
        return self.result

