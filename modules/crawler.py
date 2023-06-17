import requests
import logging
import os
import re
import ipdb

from modules.utilities import request_get, extract_vul_obj_offset_and_size, regx_get
from bs4 import BeautifulSoup
from bs4 import element

syzbot_host_url = "https://syzkaller.appspot.com/"
num_of_elements = 8

syzbot_bug_base_url = "bug?id="
syzbot_bug_ext_url = "bug?extid="
supports = {
  0:syzbot_bug_base_url,
  1:syzbot_bug_ext_url
}

class Crawler:
  def __init__(self,
              url="https://syzkaller.appspot.com/",
              debug=False):
  
    self.url = url
    self.cases = {}
    self.patches = {}
    self.logger = None
    self.logger2file = None
    self.init_logger(debug)
    # print(debug)

  def init_logger(self, debug):
    handler = logging.FileHandler("{}/info".format(os.getcwd()))
    format =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(format)
    self.logger = logging.getLogger(__name__)
    self.logger2file = logging.getLogger("log2file")
    if debug:
      self.logger.setLevel(logging.DEBUG)
      self.logger.propagate = True
      self.logger2file.setLevel(logging.DEBUG)
      self.logger2file.propagate = True
    else:
      self.logger.setLevel(logging.INFO)
      self.logger.propagate = False
      self.logger2file.setLevel(logging.INFO)
      self.logger2file.propagate = False
    self.logger2file.addHandler(handler)

  def run_one_case(self, hash, flag):
    self.logger.info("retreive one case: %s",hash)
    try:
      bug_url = supports[flag]
      self.logger.debug("{}{}{}".format(syzbot_host_url, bug_url, hash))
      url = syzbot_host_url + bug_url + hash
    except IndexError:
      print("url not support")

    if self.retreive_case(url, hash) == -1:
      return
    self.cases[hash]['title'] = self.get_title_of_case(url, hash)
    patch = self.get_patch_of_case(url, hash)
    if patch != None:
      self.cases[hash]['patch'] = patch

  def get_title_of_case(self, url, hash=None, text=None):
    if hash==None and text==None:
      self.logger.info("No case given")
      return None
    if hash!=None:
      req = requests.request(method='GET', url=url)
      soup = BeautifulSoup(req.text, "html.parser")
    else:
      soup = BeautifulSoup(text, "html.parser")
    title = soup.body.b.contents[0]
    return title
  
  def get_patch_of_case(self, url, hash):
    patch = None
    req = requests.request(method='GET', url=url)
    soup = BeautifulSoup(req.text, "html.parser")
    mono = soup.find("span", {"class": "mono"})
    if mono == None:
      return patch
    try:
      patch = mono.contents[1].attrs['href']
    except:
      pass 
    return patch

  def retreive_case(self, url, hash):
    self.cases[hash] = {}
    detail = self.request_detail(url)
    print(detail)
    # TODO: 不需要这样数量的限定，但是也要找到一个方法来限制一下
    # if len(detail) < num_of_elements:
    #   self.logger.error("Failed to get detail of a case {}".format(url))
    #   self.cases.pop(hash)
    #   return -1
    self.cases[hash]["kernel"] = detail[0]
    self.cases[hash]["commit"] = detail[1]
    self.cases[hash]["syzkaller"] = detail[2]
    self.cases[hash]["config"] = detail[3]
    self.cases[hash]["syz_repro"] = detail[4]
    self.cases[hash]["log"] = detail[5]
    self.cases[hash]["c_repro"] = detail[6]
    self.cases[hash]["time"] = detail[7]
    self.cases[hash]["manager"] = detail[8]
    self.cases[hash]["report"] = detail[9]
    self.cases[hash]["vul_offset"] = detail[10]
    self.cases[hash]["obj_size"] = detail[11]

  def request_detail(self, url, index=1):
    """
    index 默认的值是1 也就是获取第一个的配置来build
    """
    print(url)
    tables = self.__get_table(url)
    if tables == []:
      print("error occur in request_detail: {}".format(hash))
      self.logger2file.info("[Failed] {} error occur in request_detail".format(url))
      return []
    count = 0
    for table in tables:
      if table.text.find('Crash') != -1:
        for case in table.tbody.contents:
          if type(case) == element.Tag:
            kernel = case.find('td', {"class": "kernel"})
            if kernel.text == "upstream":
              self.logger.debug("Find kernel: '{}'".format(kernel.text))
            elif kernel.text == "linux-next":
              self.logger.debug("Find kernel: '{}'".format(kernel.text))
              pass
            else:
              self.logger.debug("Find kernel: '{}'".format(kernel.text))
              # TODO: 基本只要不是linux-next 就可以成功
              # linux-next 的commit 不能够顺利切换
              # continue
              pass
            count += 1
            if count < index:
              continue
            try:
              manager = case.find('td', {"class": "manager"})
              manager_str = manager.text
              time = case.find('td', {"class": "time"})
              time_str = time.text
              tags = case.find_all('td', {"class": "tag"})
              try:
                kernel_url = tags[0].next.attrs['href']
                kernel = kernel_url[:kernel_url.index(".git")+len(".git")]
              except:
                self.logger.info("kernel url is missing.{0}".format(kernel_url))
                break
              m = re.search(r'id=([0-9a-z]*)', kernel_url)
              commit = m.groups()[0]
              self.logger.debug("Kernel commit: {}".format(commit))
              m = re.search(r'commits\/([0-9a-z]*)', tags[1].next.attrs['href'])
              syzkaller = m.groups()[0]
              self.logger.debug("Syzkaller commit: {}".format(syzkaller))
              config = syzbot_host_url + case.find('td', {"class": "config"}).next.attrs['href']
              self.logger.debug("Config URL: {}".format(config))
              repros = case.find_all('td', {"class": "repro"})
              log = syzbot_host_url + repros[0].next.attrs['href']
              self.logger.debug("Log URL: {}".format(log))
              report = syzbot_host_url + repros[1].next.attrs['href']
              self.logger.debug("Log URL: {}".format(report))
              r = request_get(report)
              report_list = r.text.split('\n')
              offset, size, _ = extract_vul_obj_offset_and_size(report_list)
              try:
                syz_repro = syzbot_host_url + repros[2].next.attrs['href']
                self.logger.debug("Testcase URL: {}".format(syz_repro))
              except:
                self.logger.info("Repro is missing. Failed to retrieve case {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                syz_repro = None
              try:
                c_repro = syzbot_host_url + repros[3].next.attrs['href']
                self.logger.debug("C prog URL: {}".format(c_repro))
              except:
                c_repro = None
                self.logger.info("No c prog found")
            except:
              self.logger.info("Failed to retrieve case {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
              continue
            self.logger.info("get table ")
            return [kernel, commit, syzkaller, config, syz_repro, log, c_repro, time_str, manager_str, report, offset, size]
        break
    self.logger2file.info("[Failed] {} fail to find a proper crash".format(url))
    return []

  def __get_table(self, url):
    self.logger.info("Get table from {}".format(url))
    req = requests.request(method='GET', url=url)
    soup = BeautifulSoup(req.text, "html.parser")
    tables = soup.find_all('table', {"class": "list_table"})
    if len(tables) == 0:
      print("Fail to retrieve bug cases from list_table")
      return []
    return tables