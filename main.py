import argparse, os, stat, sys
from queue import Empty
import json
import multiprocessing, threading
import gc
import ipdb

sys.path.append(os.getcwd())
from modules import Crawler, Deployer
from subprocess import call
from modules.utilities import urlsOfCases, urlsOfCases, FOLDER, CASE

def args_parse():
  parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                   description='Deploy crash cases from syzbot\n'
                                   'eg. python syzscope -u https://syzkaller.appspot.com/bug?id=0ca897284a4e1bbc149ad96f15917e8b31a85d70\n')
  parser.add_argument('-u', '--url', nargs='?', action='store', 
                      help='Indicate an URL for automatically crawling and running.\n'')')
  parser.add_argument('--install-requirements', action='store_true',
                      help='Install required packages and compile essential tools')
  parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
  parser.add_argument('--force', action='store_true',
                        help='Force to run all cases even it has finished\n')
  parser.add_argument('-M', '--max', nargs='?',
                        default='-1',
                        help='maximum of kernel that compiling at the same time. Default is unlimited.')

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
  # TODO: 这里默认的配置是第0个
  index = 0
  dp = Deployer(index=index,
                debug=args.debug, 
                max=int(args.max_compiling_kernel_concurrently)
               )
  dp.deploy(hash_val, case)
  del dp

# multiprocessing
def prepare_cases(index, args):
  while(1):
    lock.acquire(blocking=True)
    try:
      hash_val = g_cases.get(block=True, timeout=3)
      if hash_val in ignore:
        rest.value -= 1
        lock.release()
        continue
      print("Thread {}: run case {} [{}/{}] left".format(index, hash_val, rest.value-1, total))
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
  while(1):
    lock.acquire(blocking=True)
    try:
      hash_val = g_cases.get(block=True, timeout=3)
      if hash_val in ignore:
        rest.value -= 1
        lock.release()
        continue
      print("run case {} [{}/{}] left".format(hash_val, rest.value-1, total))
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
    ret=urlsOfCases(path, CASE)
  else:
    ret=urlsOfCases(path, FOLDER)
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

def build_work_dir():
  work_path = os.path.join(os.getcwd(), "work")
  os.makedirs(work_path, exist_ok=True)
  incomp = os.path.join(work_path, "incomplete")
  comp = os.path.join(work_path, "completed")
  os.makedirs(incomp, exist_ok=True)
  os.makedirs(comp, exist_ok=True)

if __name__ == '__main__':
  args = args_parse()

  if install_requirments() != 0:
    print("Fail to install requirements.")
    exit(0)
  if args.install_requirements:
    exit(0)
  if not check_requirements():
    print("No essential components found. Install them by --install-requirements")
    exit(0)

  if args.url == None:
    print("must set url")
    exit(-1)
  if not args.url.startswith("https://syzkaller.appspot.com/"):
    print("url must be https://syzkaller.appspot.com/")
    exit(-1)
    
  print("[*] url: {}".format(args.url))
  check_kvm()

  ignore = []
  build_work_dir()

  # print(args.debug)
  crawler = Crawler(debug=args.debug)
  if args.url != None:
    # https://syzkaller.appspot.com/bug?id=1bef50bdd9622a1969608d1090b2b4a588d0c6ac 
    if args.url.__contains__("bug?id="):
      idx = args.url.index("bug?id=")+len("bug?id=")
      hash = args.url[idx:]
      crawler.run_one_case(hash,0)
    # https://syzkaller.appspot.com/bug?extid=dcc068159182a4c31ca3
    elif args.url.__contains__("?extid="):
      idx = args.url.index("?extid=")+len("?extid=")
      hash = args.url[idx:]
      crawler.run_one_case(hash,1)
    else:
      print("url format not support")
      exit(-1)

  parallel_count = 0
  manager = multiprocessing.Manager()
  lock = threading.Lock()
  g_cases = manager.Queue()
  for key in crawler.cases:
    g_cases.put(key)
  l = list(crawler.cases.keys())
  total = len(l)
  rest = manager.Value('i', total)


  # for i in range(0,min(parallel_max,total)):
  #   x = threading.Thread(target=prepare_cases, args=(i, args,), name="lord-{}".format(i))
  #   x.start()
  prepare_case(args)