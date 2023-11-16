import requests
import logging
import os, sys
from modules.utilities import request_get, extract_vul_obj_offset_and_size, regx_get
from bs4 import BeautifulSoup
from prettytable import PrettyTable
from modules import Datastorer

syzbot_host_url = "https://syzkaller.appspot.com/"
syzbot_bug_base_url = "bug?id="
syzbot_bug_ext_url = "bug?extid="
supports = {
    0: syzbot_bug_base_url,
    1: syzbot_bug_ext_url
}


class Crawler():
    def __init__(self,
                 data,
                 url,
                 type,
                 debug = False):

        if not isinstance(data, Datastorer):
            print("data format can't support!")
            exit(-1)

        self.data = data
        # url type 0,1 or othres
        self.type = type

        self.data.url = url

        # origin website
        self.soup = None
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

    def parse(self):
        try:
            bug_url = supports[self.type]
            self.logger.debug("{}{}{}".format(syzbot_host_url, bug_url, hash))
            url = syzbot_host_url + bug_url + self.data.hash
            if url != self.data.url:
                print("cheking url failed!\n")
                exit(-1)
        except IndexError:
            print("url not support")
            return

        if self.data.hash is not None:
            req = requests.request(method='GET', url=url)
            self.soup = BeautifulSoup(req.text, "html.parser")
            if not self.soup:
                print('soup is none.')
                exit(-1)

        self.data.title = self.__parse_title()
        self.data.patch = self.__parse_patch()
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
            self.data.prepare(idx)
            self.__parse_kernel_from_case(idx, case)
            self.__parse_commit_from_case(idx, case)
            self.__parse_config_from_case(idx, case)
            self.__parse_log_from_case(idx, case)
            self.__parse_manager_from_case(idx, case)
            if self.data.assets:
                self.__parse_assets_from_case(idx, case)

    # we assume every vulnerability record will contain at least entry which can satisfy our demands
    # let user choice which is better ?
    def __parse_table_index(self, table):
        # FIXME: consider this is no upstream kernel crash
        # like https://syzkaller.appspot.com/bug?extid=c53d4d3ddb327e80bc51
        all_cases = table.tbody.find_all('tr')
        return all_cases

    def __parse_kernel_from_case(self, idx, case):
        cols = case.find_all("td", {"class": "kernel"})
        kernel = cols[0].contents[0]
        if kernel is None:
            print("[-] Warning: kernel is none in url: {}".format(self.data.url))
        else:
            self.data.cases[idx]['kernel'] = kernel
            print("[+] kernel: ", kernel)

        if self.data.cases[idx]['kernel'] == "upstream":
            self.data.cases[idx]["is_upstream"] = True

    def __parse_commit_from_case(self, idx, case):
        cols = case.find_all("td", {"class": "tag"})
        if self.data.cases[idx]['is_upstream']:
            commits = cols[0].contents[0].contents[0]
        else:
            commits = cols[0].contents[0].attrs['href']
        syzkaller = cols[1].contents[0].contents[0]
        if commits is None or syzkaller is None:
            print("[-] Warning: commits or syzkaller is none in url: {}".format(self.data.url))
        else:
            self.data.cases[idx]["commit"] = commits
            print("[+] commit: ", commits)
            self.data.cases[idx]["syzkaller"] = syzkaller
            print("[+] syzkaller: ", syzkaller)

    def __parse_config_from_case(self, idx, case):
        ok = self.data.url.index("bug")
        if ok == -1:
            print("[-] Warning: bug not found in {}".format(self.data.url))
        else:
            prefix = self.data.url[:ok]
            config = case.find("td", {"class": "config"})
            config = prefix + config.contents[0].attrs['href']
            self.data.cases[idx]['config'] = config
            print("[+] config: ", config)
            self.__parse_compiler_version_from_config(idx, config)
            # if self.dst is not None:
            #     req = requests.request(method='GET', url=new_url)
            #     with os.open(os.path.join(self.dst, 'config'), os.O_RDWR | os.O_CREAT) as fd:
            #         os.write(fd, req.text.encode())
            #         os.close(fd)

    def __parse_log_from_case(self, idx, case):
        ok = self.data.url.index("bug")
        if ok == -1:
           print("[-] Warning: bug not found in {}".format(self.data.url))
        else:
            prefix = self.data.url[:ok]
            all = case.find_all("td", {"class": "repro"})
            log,report,syz,cpp,_ = case.find_all("td", {"class": "repro"})

            if log.contents:
                log = prefix + log.contents[0].attrs['href']
                self.data.cases[idx]['log'] = log
                print("[+] console_log: ", log)

            if report.contents:
                report = prefix + report.contents[0].attrs['href']
                self.data.cases[idx]['report'] = report
                print("[+] report: ", report)

            if syz.contents:
                syz = prefix +  syz.contents[0].attrs['href']
                self.data.cases[idx]['syz'] = syz
                print("[+] syz_repro: ", syz)

            if cpp.contents:
                cpp = prefix + cpp.contents[0].attrs['href']
                self.data.cases[idx]['cpp'] = cpp
                print("[+] cpp_repro: ", cpp)

    def __parse_assets_from_case(self, idx, case):
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
            print("[-] Warning: manager is none in url: {}".format(self.data.url))
        else:
            self.data.cases[idx]['manager'] = manager
            print("[+] manager: ", manager)

    def __parse_compiler_version_from_config(self, idx, config):
        req = requests.request(method='GET', url=config).text.encode()
        start = req.find(b"CONFIG_CC_VERSION_TEXT=") + len("CONFIG_CC_VERSION_TEXT=")
        if start != -1:
            end = req.find(b"\n", start)
        if end != -1:
            compiler = req[start+1:end-1].decode('utf-8')
            if "gcc" in compiler:
                version = compiler.strip().split(' ')[-1]
                self.data.cases[idx]['version'] = int(version.split('.')[0])
                self.data.cases[idx]['gcc'] = "gcc " + version
            elif "clang" in compiler:
                version = compiler.strip().split(' ')[-1]
                self.data.cases[idx]['version'] = int(version.split('.')[0])
                self.data.cases[idx]['clang'] = "clang "+ version
            else:
                # FIXME: when it's not clang or gcc, will crash in show() function
                print("do not support this compiler")
        else:
            print("[-] Warning: can not found gcc version in config")

    def show(self):
        table = PrettyTable()
        table.field_names = ["idx", "kernel", "syzkaller", "compiler", "syz", "cpp", "manager"]
        # for idx, case in self.data.cases:
        for idx, case in self.data.cases.items():
            table.add_row([str(idx),
                           str(case["kernel"]),
                           str(case["syzkaller"]),
                           str(case["gcc"]) if case["gcc"] else str(case["clang"]),
                           "True" if case["syz"] else "None",
                           "True" if case["cpp"] else "None",
                           str(case["manager"])
                           ])
        table.title = self.data.title
        print(table)
