import argparse, os, stat, sys
from queue import Empty
import json
import multiprocessing, threading
import gc

sys.path.append(os.getcwd())
from subprocess import call
from modules.utilities import urlsOfCases, urlsOfCases, FOLDER, CASE
from modules import Datastorer
from modules.crawler import Crawler
from modules.deployer import Deployer
from modules.extracter import Extracter

def args_parse():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Deploy crash cases from syzbot\n')
    parser.add_argument('-u', '--url', nargs='?', action='store', help='the url for automatically crawling and building.\n'')')
    parser.add_argument('-d', '--dst', nargs='?', action='store', help='destination to store.\n'')')
    parser.add_argument("--logs", action="store_true", default=False, help="crawling all the logs from the url, default=false.\n")
    parser.add_argument("--assets", action="store_true", default=False, help="crawling assets or not, default=false.\n")
    parser.add_argument('--install-requirements', action='store_true',  help='Install required packages and compile essential tools')
    parser.add_argument('--debug', action='store_true', help='enable debug mode')
    parser.add_argument('--force', action='store_true', help='Force to run all cases even it has finished\n')
    parser.add_argument('--max', nargs='?', default='-1', help='maximum of kernel that compiling at the same time. Default is unlimited.')

    args = parser.parse_args()
    return args


def check_kvm():
    proj_path = os.path.join(os.getcwd())
    check_kvm_path = os.path.join(proj_path, "scripts/check_kvm.sh")
    st = os.stat(check_kvm_path)
    os.chmod(check_kvm_path, st.st_mode | stat.S_IEXEC)
    r = call([check_kvm_path], shell=False)
    if r == 1:
        exit(0)


def cache_cases(cases):
    work_path = os.getcwd()
    cases_json_path = os.path.join(work_path, "work/cases.json")
    with open(cases_json_path, 'w') as f:
        json.dump(cases, f)
        f.close()


def read_cases_from_cache():
    cases = {}
    work_path = os.getcwd()
    cases_json_path = os.path.join(work_path, "work/cases.json")
    if os.path.exists(cases_json_path):
        with open(cases_json_path, 'r') as f:
            cases = json.load(f)
            f.close()
    return cases


def deploy_one_case(args, hash_val):
    case = crawler.cases[hash_val]
    # TODO 这里默认的配置是第0个
    index = 0
    dp = Deployer(index=index,
                  debug=args.debug,
                  max=int(args.max)
                  )
    dp.deploy(hash_val, case)
    del dp


# multiprocessing
def prepare_cases(index, args):
    lock = threading.Lock()
    while (1):
        lock.acquire(blocking=True)
        try:
            hash_val = g_cases.get(block=True, timeout=3)
            if hash_val in ignore:
                rest.value -= 1
                lock.release()
                continue
            print("Thread {}: run case {} [{}/{}] left".format(index, hash_val, rest.value - 1, total))
            rest.value -= 1
            lock.release()
            x = multiprocessing.Process(target=deploy_one_case, args=(index, args, hash_val,), name="lord-{}".format(i))
            x.start()
            x.join()
            gc.collect()
            # remove_using_flag(index)
        except Empty:
            lock.release()
            break
    print("Thread {} exit->".format(index))


# only one
def prepare_case(args):
    while (1):
        lock.acquire(blocking=True)
        try:
            hash_val = g_cases.get(block=True, timeout=3)
            if hash_val in ignore:
                rest.value -= 1
                lock.release()
                continue
            print("run case {} [{}/{}] left".format(hash_val, rest.value - 1, total))
            rest.value -= 1
            lock.release()
            deploy_one_case(args, hash_val)
            gc.collect()
            # remove_using_flag()
        except Empty:
            lock.release()
            break


def get_hash(path):
    ret = []
    log_path = os.path.join(path, "log")
    if os.path.exists(log_path):
        ret = urlsOfCases(path, CASE)
    else:
        ret = urlsOfCases(path, FOLDER)
    print("The hash of {}".format(path))
    for each in ret:
        print(each)


# def remove_using_flag(index):
#   project_path = os.getcwd()
#   flag_path = "{}/tools/linux-{}/THIS_KERNEL_IS_BEING_USED".format(project_path,index)
#   if os.path.isfile(flag_path):
#     os.remove(flag_path)

def install_requirments():
    proj_path = os.path.join(os.getcwd())
    requirements_path = os.path.join(proj_path, "scripts/requirements.sh")
    st = os.stat(requirements_path)
    os.chmod(requirements_path, st.st_mode | stat.S_IEXEC)
    return call([requirements_path], shell=False)


def check_requirements():
    tools_path = os.path.join(os.getcwd(), "tools")
    env_stamp = os.path.join(tools_path, ".stamp/ENV_SETUP")
    return os.path.isfile(env_stamp)


if __name__ == '__main__':
    # logging.getLogger().setLevel(logging.INFO)
    args = args_parse()

    # if install_requirments() != 0:
    #   print("Fail to install requirements.")
    #   exit(0)
    # if args.install_requirements:
    #   exit(0)
    # if not check_requirements():
    #   print("No essential components found. Install them by --install-requirements")
    #   exit(0)
    if args.url is None:
        print("must set url -u/--url")
        exit(-1)
    if not args.url.startswith("https://syzkaller.appspot.com/"):
        print("url must be has the prefix https://syzkaller.appspot.com/")
        exit(-1)

    if args.dst is None:
        print("must set dest -d/--dest")
        exit(-1)

    if not os.path.isabs(args.dst):
        args.dst = os.path.abspath(args.dst)

    if not os.path.exists(args.dst):
        print("destination don't existed")
        exit(-1)

    print("[*] url: {}".format(args.url))

    # NOTE: checking system environment
    # check_kvm()
    # ignore = []

    # NOTE: checking url
    if args.url != None:
        # https://syzkaller.appspot.com/bug?id=1bef50bdd9622a1969608d1090b2b4a588d0c6ac
        if args.url.__contains__("bug?id="):
            idx = args.url.index("bug?id=") + len("bug?id=")
            hash = args.url[idx:]
            url_flag = 0
        # https://syzkaller.appspot.com/bug?extid=dcc068159182a4c31ca3
        elif args.url.__contains__("?extid="):
            # test for https://syzkaller.appspot.com/bug?extid=60db9f652c92d5bacba4
            idx = args.url.index("?extid=") + len("?extid=")
            hash = args.url[idx:]
            url_flag = 1
        else:
            print("url format not support")
            url_flag = 2
    else:
        print("must provide a valid url!")
        exit(-1)

    # NOTE: checking and building workdir
    args.dst = os.path.join(args.dst, hash[:8])
    try:
        os.mkdir(args.dst)
    except FileExistsError:
        co = input("{} existed, please check and continue.(y/n) ?\n".format(args.dst))
        if co == "y":
            pass
        elif co == "n":
            pass
        else:
            print('input error! get out.')
            exit(-1)
    except PermissionError:
        print("{} permissing error, please check again".format(args.dst))
        exit(-1)
    except FileNotFoundError:
        print("{} not found, please check again".format(args.dst))
        exit(-1)
    except OSError as error:
        print("{} cause os error, please check again".format(args.dst))
        exit(-1)
    else:
        print("[*] dst: {}".format(args.dst))
        # print("whatever failed in mkdir {}",args.dst)
        # os.system("rm -rf {}".format(args.dst))
        # exit(-1)
    data = Datastorer()
    crawler = Crawler(data, args.url, url_flag, logs_flag=True)
    print("[*] crawlering....")
    crawler.parse(hash)
    crawler.show()
    print("[*] crawling done")
    which = int(input("chose one: "))
    if which < len(data.cases):
        print("[*] deplying")
        import ipdb; ipdb.set_trace();
        deployer = Deployer(data.cases, args.dst, index=which)
        print("[*] deploying done")
    else:
        print('fuck off. hacker!')

    # parallel_count = 0
    # manager = multiprocessing.Manager()
    # lock = threading.Lock()
    # g_cases = manager.Queue()
    # for key in crawler.cases:
    #   g_cases.put(key)
    # l = list(crawler.cases.keys())
    # total = len(l)
    # rest = manager.Value('i', total)
    #
    #
    # # for i in range(0,min(parallel_max,total)):
    # #   x = threading.Thread(target=prepare_cases, args=(i, args,), name="lord-{}".format(i))
    # #   x.start()
    # prepare_case(args)

    # temporary use to create img
    # bullseye disk
    """
    bullseye = os.path.join(dir(args.dst))
    os.system("cp -r {} .".format(),)

    bookworm = os.path.join(dir(args.dst))
    os.system("cp -r {} .".format(),)
    """

    # syzbot config

    """
    {
	"target": "linux/amd64",
	"http": "0.0.0.0:56741",
	"workdir": "/home/inspur/syzbot/23bbb17a/workdir",
	"kernel_obj": "/home/inspur/syzbot/23bbb17a/kernel",
	"image": "/home/inspur/bullseye/bullseye.img",
	"sshkey": "/home/inspur/bullseye/bullseye.id_rsa",
	"syzkaller": "/home/inspur/syzbot/23bbb17a/syzkaller",
	"procs": 8,
	"type": "qemu",
	"max_crash_logs": 20,
	"cover": true,
	"raw_cover" : true,
	"reproduce": false,
	"preserve_corpus": false,
	"vm": {
		"count": 8,
		"kernel": "/home/inspur/syzbot/0ca89728/kernel/arch/x86/boot/bzImage",
		"cpu": 4,
		"mem":
        }
    }
    """

    # run.sh

    """
    qemu-system-x86_64 \
        -kernel ./kernel/arch/x86/boot/bzImage \
        -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=QUZ" \
        -hda ./bullseye/bullseye.img \
        -net user,hostfwd=tcp:0.0.0.0:31338-:22 -net nic \
        -enable-kvm \
        -cpu host \
        -nographic \
        -m 8G \
        -smp 4 \
        -pidfile vm.pid \
        2>&1 | tee vm.log
    """

    # git checkout syzkaller
    """
    not implemented now
    """



