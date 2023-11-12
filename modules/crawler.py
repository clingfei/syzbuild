import requests
import logging
import subprocess
import os, sys
import re
from modules.utilities import request_get, extract_vul_obj_offset_and_size, regx_get
from bs4 import BeautifulSoup
from bs4 import element

syzbot_host_url = "https://syzkaller.appspot.com/"
num_of_elements = 8

syzbot_bug_base_url = "bug?id="
syzbot_bug_ext_url = "bug?extid="
supports = {
    0: syzbot_bug_base_url,
    1: syzbot_bug_ext_url
}

UPSTREAM_LINUX = "/home/inspur/foorbar/linux"


class Crawler:
    def __init__(self,
                 dst,
                 url,
                 debug=False):

        self.url = url
        self.dst = dst
        self.cases = {}
        self.patches = {}
        self.commits = None
        self.syzkaller = None
        self.logger = None
        self.workDir = ""
        self.init_logger(debug)

    def init_logger(self, debug):
        handler = logging.StreamHandler(sys.stderr)
        format = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(format)
        self.logger = logging.getLogger(__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
            self.logger.propagate = True
        else:
            self.logger.setLevel(logging.INFO)
            self.logger.propagate = False
        self.logger.addHandler(handler)

    def run_one_case(self, hash, url_flag, assets_flag, logs_flag):
        # self.logger.info("retrieve one case: %s", hash)
        try:
            bug_url = supports[url_flag]
            self.logger.debug("{}{}{}".format(syzbot_host_url, bug_url, hash))
            url = syzbot_host_url + bug_url + hash
        except IndexError:
            print("url not support")
            return

        if self.retreive_case(url, hash) == -1:
            return

        if hash is not None:
            req = requests.request(method='GET', url=url)
            soup = BeautifulSoup(req.text, "html.parser")

        self.cases[hash]['title'] = self.get_title_of_case(soup)
        print("[+] title: ", self.cases[hash]['title'])
        patch = self.get_patch_of_case(soup)
        if patch is not None:
            self.cases[hash]['patch'] = patch
            print("[+] patch: ", self.cases[hash]['patch'])

        tr = self.get_best_index(soup)
        commits, syzkaller = self.get_commit_of_case(tr)
        if commits is None or syzkaller is None:
            print("Warning!!! commits or syzkaller is None in url: {}".format(url))
        else:
            self.cases[hash]['url'] = url
            self.cases[hash]['commits'] = commits
            self.cases[hash]['syzkaller'] = syzkaller
            print('[+] kernel={}, syzkaller={}'.format(commits, syzkaller))

        self.get_config_of_case(tr, url)
        self.get_console_log_of_case(tr, url)
        self.get_report_of_case(tr, url)
        if assets_flag:
            self.get_asserts_of_case(tr)
        self.store_to_files(hash)

    def get_title_of_case(self, soup):
        if soup is None:
            print("soup is None")
            return
        title = soup.body.b.contents[0]
        return title

    def get_patch_of_case(self, soup):
        patch = None
        mono = soup.find("span", {"class": "mono"})
        if mono is None:
            return patch
        try:
            patch = mono.contents[1].attrs['href']
        except:
            pass
        return patch

    # select the first upstream kernel, console log
    # we assume every vulnerability record will contain at least entry which can satisfy our demands
    def get_best_index(self, soup):
        tables = soup.find_all("table", {"class": "list_table"})
        for table in tables:
            if table.caption is not None:
                if table.caption.contents[0].find("Crashes") != -1 and \
                        table.caption.contents[0].find("Crashes") is not None:
                    # FIXME: consider this is no upstream kernel crash
                    # like https://syzkaller.appspot.com/bug?extid=c53d4d3ddb327e80bc51
                    for tr in table.tbody.find_all('tr'):
                        if tr.find("td", {"class": "kernel"}).contents[0] == "upstream" \
                                and tr.find("td", {"class": "repro"}).contents[0].contents[0] == "console log":
                            return tr

    def get_commit_of_case(self, tr):
        cols = tr.find_all("td", {"class": "tag"})
        commits = cols[0].contents[0].contents[0]
        syzkaller = cols[1].contents[0].contents[0]
        return commits, syzkaller

    def get_config_of_case(self, tr, url):
        idx = url.index("bug")
        if idx == -1:
            print("Warning: bug not found in url!!!")
        else:
            prefix = url[:idx]
            config = tr.find("td", {"class": "config"})
            new_url = prefix + config.contents[0].attrs['href']
            if self.dst is not None:
                req = requests.request(method='GET', url=new_url)
                with os.open(os.path.join(self.dst, 'config'), os.O_RDWR | os.O_CREAT) as fd:
                    os.write(fd, req.text.encode())
                    os.close(fd)

    def get_console_log_of_case(self, tr, url):
        idx = url.index("bug")
        if idx == -1:
            print("Warning: buf not found in url!!!")
        else:
            prefix = url[:idx]
            console = tr.find("td", {"class": "repro"}).contents[0].attrs['href']
            new_url = prefix + console
            if self.dst is not None:
                print("[+] console_log: ", new_url)
                req = requests.request(method='GET', url=new_url)
                with os.open(os.path.join(self.dst, 'console_log'), os.O_RDWR | os.O_CREAT) as fd:
                    os.write(fd, req.text.encode())
                    os.close(fd)

    def get_report_of_case(self, tr, url):
        idx = url.index("bug")
        if idx == -1:
            print("Warning: buf not found in url!!!")
        else:
            prefix = url[:idx]
            reports = tr.find_all("td", {"class": "repro"})
            for report in reports:
                if report.contents[0].contents[0] == "report":
                    new_url = prefix + report.contents[0].attrs['href']
                    print("[+] report url: ", new_url)
                    req = requests.request(method='GET', url=new_url)
                    with os.open(os.path.join(self.dst, 'report'), os.O_RDWR | os.O_CREAT) as fd:
                        os.write(fd, req.text.encode())
                        os.close(fd)
                    return

    def get_asserts_of_case(self, tr):
        assets = tr.find("td", {"class": "assets"})
        if assets is None:
            return
        spans = assets.find_all("span", {"class": "no-break"})
        for span in spans:
            os.chdir(self.dst)
            os.system("wget " + span.contents[1].attrs['href'])
            print(span.contents[1].attrs['href'])

    def get_gcc_version_from_config(self):
        pass


    def store_to_files(self, hash):
        os.chdir(self.dst)
        os.system("echo " + self.cases[hash]['url'] + " > url")
        # os.system("echo " + self.cases[hash]['syzkaller'] + " > syzkaller")
        # os.system("echo " + self.cases[hash]['commit'] + " > kernel")
        os.system("echo " + self.cases[hash]['title'] + " > description")
        # FIXME: hard-coded linux
        # status = os.system("cp -r /home/spark/foobar/linux {}".format(os.path.join(self.dst, "kernel")))
        # if not status:
        #     print("copy linux folder to kernel failed!\n")
        #     exit(-1)
        kernel = os.path.join(os.path.dirname(self.dst), "linux")
        if not os.path.exists(kernel):
            print('linux folder do not existed!')
            exit(-1)

        syzkaller = os.path.join(os.path.dirname(self.dst), "syzkaller")
        if not os.path.exists(syzkaller):
            print('linux folder do not existed!')
            exit(-1)

        try:
            res = subprocess.run(["cp", "-r", "{}".format(kernel),"{}".format(os.path.join(self.dst, "kernel"))], check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print("subprocess failed ", e)
            exit(-1)

        print("git reset " + self.cases[hash]['commits'])
        os.chdir(os.path.join(self.dst, "kernel"))
        os.system("git checkout -q " + self.cases[hash]['commits'])
        os.chdir("..")
        os.system("cp config kernel/.config")

        # FIXME: hard-coded syzkaller
        try:
            res = subprocess.run(["cp", "-r", "{}".format(syzkaller),"{}".format(os.path.join(self.dst, "syzkaller"))], check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print("subprocess failed ", e)
            exit(-1)
        os.chdir(os.path.join(self.dst, "syzkaller"))
        os.system("git checkout -q " + self.cases[hash]['syzkaller'])
        os.chdir("..")

    # def get_title_of_case(self, url, hash=None, text=None):
    #     if hash == None and text == None:
    #         self.logger.info("No case given")
    #         return None
    #     if hash != None:
    #         req = requests.request(method='GET', url=url)
    #         soup = BeautifulSoup(req.text, "html.parser")
    #     else:
    #         soup = BeautifulSoup(text, "html.parser")
    #     title = soup.body.b.contents[0]
    #     return title

    # def get_patch_of_case(self, url, hash):
    #     patch = None
    #     req = requests.request(method='GET', url=url)
    #     soup = BeautifulSoup(req.text, "html.parser")
    #     mono = soup.find("span", {"class": "mono"})
    #     if mono == None:
    #         return patch
    #     try:
    #         patch = mono.contents[1].attrs['href']
    #     except:
    #         pass
    #     return patch

    def retreive_case(self, url, hash):
        self.cases[hash] = {}
        detail = self.request_detail(url)
        self.logger.info("get table")
        self.logger.debug(detail)
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
                                kernel = kernel_url[:kernel_url.index(".git") + len(".git")]
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
                                self.logger.info(
                                    "Repro is missing. Failed to retrieve case {}{}{}".format(syzbot_host_url,
                                                                                              syzbot_bug_base_url,
                                                                                              hash))
                                syz_repro = None
                            try:
                                c_repro = syzbot_host_url + repros[3].next.attrs['href']
                                self.logger.debug("C prog URL: {}".format(c_repro))
                            except:
                                c_repro = None
                                self.logger.info("No c prog found")
                        except:
                            self.logger.info(
                                "Failed to retrieve case {}{}{}".format(syzbot_host_url, syzbot_bug_base_url, hash))
                            continue
                        return [kernel, commit, syzkaller, config, syz_repro, log, c_repro, time_str, manager_str,
                                report, offset, size]
                break
        self.logger.info("[Failed] {} fail to find a proper crash".format(url))
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
