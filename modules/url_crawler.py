import csv
import os

import requests
from bs4 import BeautifulSoup
from bs4 import element
import argparse

syzbot_host_url = "https://syzkaller.appspot.com"

# 需要记录open invalid, fixed三个页面的url和description
class UrlCrawler:
    def __init__(self,
                 url,
                 dst
                 ):

        self.url = url
        self.cases = {}
        # origin website
        self.soup = None
        self.dst = dst

    def parse(self):
        if self.url is None:
            print('invalid url')
            exit(-1)
        req = requests.request(method='GET', url=self.url)
        self.soup = BeautifulSoup(req.text, "html.parser")
        if not self.soup:
            print('soup is none.')
            exit(-1)
        tables = self.parse_table()
        if len(tables) > 1:
            for _, table in enumerate(tables):
                if table.caption is not None:
                    # self.parse_crash_table(table)
                    if table.caption.find("a", {"class", "plain"}) is not None:
                        if table.caption.find("a", {"class", "plain"}).contents[0].find("open") >= 0:
                            self.parse_crash_table(table, "open")
                        if table.caption.find("a", {"class", "plain"}).contents[0].find("moderation") >= 0:
                            self.parse_crash_table(table, "moderation")
        elif len(tables) == 1:
            self.parse_crash_table(tables[0], self.url[str.rfind(self.url, "/") + 1:])
        else:
            print("table is none. please check your url!")
            exit(-1)

    def parse_table(self):
        tables = self.soup.find_all('table', {'class': 'list_table'})
        if len(tables) == 0:
            print("Fail to retrieve bug cases from list_table")
            return []
        else:
            print("[+] table contains {} cases".format(len(tables)))
        return tables

    def parse_table_index(self, table):
        all_cases = table.tbody.find_all('tr')
        return all_cases

    def parse_crash_table(self, table, table_name):
        cases = self.parse_table_index(table)
        with open(os.path.join(self.dst, table_name + ".csv"), 'w') as fd:
            newfd = csv.writer(fd)
            for idx, case in enumerate(cases):
                if len(case.find("td", {"class": "stat"}).contents) == 0:
                    new_url = syzbot_host_url + case.find("td", {"class": "title"}).find('a', href=True).get('href')
                    title = case.find("td", {"class": "title"}).find("a").contents[0]
                    # print(title)
                    # fd.write("{},{}\n".format(title, new_url))
                    newfd.writerow([title, new_url])
            fd.close()

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Deploy crash cases from syzbot\n')
    parser.add_argument('-d', '--dst', nargs='?', action='store', help='destination to store.\n'')')

    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = args_parse()
    if args.dst is None:
        print("must set dest -d/--dest")
        exit(-1)

    crawler = UrlCrawler("https://syzkaller.appspot.com/upstream", args.dst)
    crawler.parse()
    crawler = UrlCrawler("https://syzkaller.appspot.com/upstream/fixed", args.dst)
    crawler.parse()
    crawler = UrlCrawler("https://syzkaller.appspot.com/upstream/invalid", args.dst)
    crawler.parse()

    # which = int(input("chose one: "))
    # if which < len(crawler.cases):
    #     crawler.deploy(which)
    # else:
    #     print('fuck off. hacker!')
    # print("[*] crawler done")
