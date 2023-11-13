import requests
import logging
import subprocess
import os, sys
import re
from modules.utilities import request_get, extract_vul_obj_offset_and_size, regx_get
from bs4 import BeautifulSoup
from bs4 import element
from prettytable import PrettyTable

syzbot_host_url = "https://syzkaller.appspot.com/"
num_of_elements = 8

syzbot_bug_base_url = "bug?id="
syzbot_bug_ext_url = "bug?extid="
supports = {
    0: syzbot_bug_base_url,
    1: syzbot_bug_ext_url
}

UPSTREAM_LINUX = os.environ.get('UPSTREAM_LINUX')
UPSTREAM_SYZKALLER = os.environ.get('UPSTREAM_SYZKALLER')

GCC8 = os.environ.get("GCC8")
GCC9 = os.environ.get("GCC9")
GCC10 = os.environ.get("GCC10")
GCC11 = os.environ.get("GCC11")
GCC12 = os.environ.get("GCC12")

CLANG8 = os.environ.get("CLANG8")
CLANG9 = os.environ.get("CLANG9")
CLANG10 = os.environ.get("CLANG10")
CLANG11 = os.environ.get("CLANG11")
CLANG12 = os.environ.get("CLANG12")
CLANG13 = os.environ.get("CLANG13")
CLANG14 = os.environ.get("CLANG14")
CLANG15 = os.environ.get("CLANG15")
CLANG16 = os.environ.get("CLANG16")
CLANG17 = os.environ.get("CLANG17")

class Crawler():
    def __init__(self,
                 dst,
                 url,
                 url_flag,
                 assets_flag = False,
                 logs_flag = False,
                 debug = False):

        self.url = url
        self.dst = dst
        self.url_flag = url_flag
        self.assets_flag = assets_flag
        self.logs_flag = logs_flag

        # origin website
        self.soup = None

        self.title = ""
        self.pretty = None
        self.cases = {}
        self.patch = ""

        self.__init_logger(debug)

    def __init_logger(self, debug):
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

    def parse(self, hash):
        try:
            bug_url = supports[self.url_flag]
            self.logger.debug("{}{}{}".format(syzbot_host_url, bug_url, hash))
            url = syzbot_host_url + bug_url + hash
            if url != self.url:
                print("cheking url failed!\n")
                exit(-1)
        except IndexError:
            print("url not support")
            return

        if hash is not None:
            req = requests.request(method='GET', url=url)
            self.soup = BeautifulSoup(req.text, "html.parser")
            if not self.soup:
                print('soup is none.')
                exit(-1)

        self.title = self.__parse_title()
        self.patch = self.__parse_patch()
        tables = self.__parse_tables()
        if len(tables) > 1:
            for _,table in enumerate(tables):
                # NOTE: only consider crashes table
                if table.caption is not None:
                    if table.caption.contents[0].find("Crashes") is not None:
                        self.__parse_crash_table(table)
        else:
            print("table is none.")
            exit(-1)

    def __parse_title(self):
        title = self.soup.body.b.contents[0]
        print("[+] title: ", title)
        return title

    def __parse_tables(self):
        tables = self.soup.find_all('table', {"class": "list_table"})
        if len(tables) == 0:
            print("Fail to retrieve bug cases from list_table")
            return []
        else:
            print("[+] table contains {} cases".format(len(tables)))
        return tables

    def __parse_patch(self):
        patch = None
        mono = self.soup.find("span", {"class": "mono"})
        if mono is None:
            return patch
        try:
            patch = mono.contents[1].attrs['href']
        except:
            pass
        if patch is not None:
            print("[+] patch: ", patch)
        return patch

    def __parse_crash_table(self, table):
        cases = self.__parse_table_index(table)
        for idx, case in enumerate(cases):
            self.__prepare_case(idx)
            self.__parse_kernel_from_case(idx, case)
            self.__parse_commit_from_case(idx, case)
            self.__parse_config_from_case(idx, case)
            self.__parse_log_from_case(idx, case)
            self.__parse_manager_from_case(idx, case)
            if self.assets_flag:
                self.__parse_asserts_from_case(idx, case)

    # we assume every vulnerability record will contain at least entry which can satisfy our demands
    # let user choice which is better ?
    def __parse_table_index(self, table):
        # FIXME: consider this is no upstream kernel crash
        # like https://syzkaller.appspot.com/bug?extid=c53d4d3ddb327e80bc51
        all_cases = table.tbody.find_all('tr')
        return all_cases

    def __prepare_case(self, idx):
        self.logger.info("prepare case")
        self.cases[idx] = {}

        self.cases[idx]["kernel"] = None
        self.cases[idx]["commit"] = None
        self.cases[idx]["syzkaller"] = None
        self.cases[idx]["config"] = None
        self.cases[idx]["gcc"] = None
        self.cases[idx]["log"] = None
        self.cases[idx]["report"] = None
        self.cases[idx]["syz"] = None
        self.cases[idx]["cpp"] = None
        if self.assets_flag:
            self.cases[idx]["assets"] = []
        self.cases[idx]["manager"] = None

        # detail = self.__run_one_case(self, url)

    def __parse_kernel_from_case(self, idx, case):
        cols = case.find_all("td", {"class": "kernel"})
        kernel = cols[0].contents[0]
        if kernel is None:
            print("[-] Warning: kernel is none in url: {}".format(self.url))
        else:
            self.cases[idx]['kernel'] = kernel
            print("[+] kernel: ", kernel)

    def __parse_commit_from_case(self, idx, case):
        cols = case.find_all("td", {"class": "tag"})
        commits = cols[0].contents[0].contents[0]
        syzkaller = cols[1].contents[0].contents[0]
        if commits is None or syzkaller is None:
            print("[-] Warning: commits or syzkaller is none in url: {}".format(self.url))
        else:
            self.cases[idx]["commit"] = commits
            print("[+] commit: ", commits)
            self.cases[idx]["syzkaller"] = syzkaller
            print("[+] syzkaller: ", syzkaller)

    def __parse_config_from_case(self, idx, case):
        ok = self.url.index("bug")
        if ok == -1:
            print("[-] Warning: bug not found in {}".format(self.url))
        else:
            prefix = self.url[:ok]
            config = case.find("td", {"class": "config"})
            config = prefix + config.contents[0].attrs['href']
            self.cases[idx]['config'] = config
            print("[+] config: ", config)
            self.__parse_gcc_version_from_config(idx, config)
            # if self.dst is not None:
            #     req = requests.request(method='GET', url=new_url)
            #     with os.open(os.path.join(self.dst, 'config'), os.O_RDWR | os.O_CREAT) as fd:
            #         os.write(fd, req.text.encode())
            #         os.close(fd)

    def __parse_log_from_case(self, idx, case):
        ok = self.url.index("bug")
        if ok == -1:
           print("[-] Warning: bug not found in {}".format(self.url))
        else:
            prefix = self.url[:ok]
            all = case.find_all("td", {"class": "repro"})
            log,report,syz,cpp,_ = case.find_all("td", {"class": "repro"})

            if log.contents:
                log = prefix + log.contents[0].attrs['href']
                self.cases[idx]['log'] = log
                print("[+] console_log: ", log)

            if report.contents:
                report = prefix + report.contents[0].attrs['href']
                self.cases[idx]['report'] = report
                print("[+] report: ", report)

            if syz.contents:
                syz = prefix +  syz.contents[0].attrs['href']
                self.cases[idx]['syz'] = syz
                print("[+] syz_repro: ", syz)

            if cpp.contents:
                cpp = prefix + cpp.contents[0].attrs['href']
                self.cases[idx]['cpp'] = cpp
                print("[+] cpp_repro: ", cpp)

    def __parse_asserts_from_case(self, idx, case):
        assets = case.find("td", {"class": "assets"})
        if assets is None:
            return
        spans = assets.find_all("span", {"class": "no-break"})
        print("[+] assets: ")
        for span in spans:
            cnt = span.contents[1].attrs['href']
            print("  {}".format(cnt))

    def __parse_manager_from_case(self, idx, case):
        cols = case.find_all("td", {"class": "manager"})
        manager = cols[0].contents[0]
        if manager is None:
            print("[-] Warning: manager is none in url: {}".format(self.url))
        else:
            self.cases[idx]['manager'] = manager
            print("[+] manager: ", manager)

    def __parse_gcc_version_from_config(self, idx, config):
        req = requests.request(method='GET', url=config).text.encode()
        start = req.find(b"CONFIG_CC_VERSION_TEXT=") + len("CONFIG_CC_VERSION_TEXT=")
        if start != -1:
            end = req.find(b"\n", start)
        if end != -1:
            gcc = req[start+1:end-1]
            self.cases[idx]['gcc'] = gcc.decode("utf-8")
        else:
            print("[-] Warning: can not found gcc version in config")

    def show(self):
        table = PrettyTable()
        table.field_names = ["idx", "kernel", "commit", "syzkaller", "gcc", "syz", "cpp", "manager"]
        # for idx, case in self.cases:
        for idx, case in self.cases.items():
            table.add_row([str(idx),
                           str(case["kernel"]),
                           str(case["commit"]),
                           str(case["syzkaller"]),
                           str(case["gcc"]),
                           "True" if case["syz"] else "None",
                           "True" if case["cpp"] else "None",
                           str(case["manager"])
                           ])
        table.title = self.title
        # print(self.title)
        print(table)

    # chose one
    def deploy(self, idx):
        with open(os.path.join(self.dst, "description"), "w") as fp:
            fp.write(self.title)

        with open(os.path.join(self.dst, "url"), "w") as fp:
            fp.write(self.url)

        self._deploy_kernel(idx)
        self._deploy_syzkaller(idx)
        self._deploy_gcc(idx)
        self._deploy_report(idx)
        if self.logs_flag:
            self._deploy_all_logs()
        else:
            self._deploy_log(idx)

    def deploy_allcases(self):
        print("not implemented now")

    def _deploy_kernel(self, idx, default=UPSTREAM_LINUX):
        if self.cases[idx]['kernel'] == "upstream":
            kernel = default
            if not os.path.exists(kernel):
                print('defalut kernel folder do not existed!')
                exit(-1)

            try:
                res = subprocess.run(["cp", "-r", "{}".format(kernel),"{}".format(os.path.join(self.dst, "kernel"))], check=True, text=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print("subprocess failed ", e)
                exit(-1)

            if self.dst is not None:
                req = requests.request(method='GET', url=self.cases[idx]['config'])
                kernel = os.path.join(self.dst, "kernel")
                with open(os.path.join(kernel, '.config'), 'wb') as fd:
                    fd.write(req.text.encode())

            os.chdir(os.path.join(self.dst, "kernel"))
            os.system("git checkout -q " + self.cases[idx]['commit'])
        elif self.cases[idx]['kernel'] == "net-next":
            print("not implemented now")
        else:
            print("not implemented now")

    def _deploy_syzkaller(self, idx, default=UPSTREAM_SYZKALLER):
        syzkaller = default
        if not os.path.exists(syzkaller):
            print('defalut syzkaller folder do not existed!')
            exit(-1)
        try:
            res = subprocess.run(["cp", "-r", "{}".format(syzkaller),"{}".format(os.path.join(self.dst, "syzkaller"))], check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print("subprocess failed ", e)
            exit(-1)

        os.chdir(os.path.join(self.dst, "syzkaller"))
        os.system("git checkout -q " + self.cases[idx]['syzkaller'])

    def _deploy_gcc(self, idx):
        """
        gcc (Debian 12.2.0-14) 12.2.0
        gcc (Debian 10.2.1-6) 10.2.1 20210110
        Debian clang version 11.0.1-2
        """
        gcc = self.cases[idx]['gcc']
        if gcc == "gcc (Debian 12.2.0-14) 12.2.0":
            print("gcc12")
        else:
            print("not implemented now")

    def deploy_clang(self, idx):
        """
        fuck
        """
        pass

    def _deploy_report(self, idx):
        req = requests.request(method='GET', url=self.cases[idx]['report'])
        with open(os.path.join(self.dst, 'report'), "wb")as fd:
            fd.write(req.text.encode())

        syzkaller = os.path.join(os.path.dirname(self.dst), "syzkaller")

    def _deploy_log(self, idx):
        req = requests.request(method='GET', url=self.cases[idx]['log'])
        with open(os.path.join(self.dst, 'log'), "wb") as fd:
            fd.write(req.text.encode())

    def _deploy_all_logs(self):
        for idx, case in self.cases.items():
            req = requests.request(method='GET', url=case['log'])
            with open(os.path.join(self.dst, 'log{}'.format(idx)), "wb") as fd:
                fd.write(req.text.encode())
