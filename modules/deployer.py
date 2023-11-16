from math import trunc
import re
import os
import sys
import requests
import datetime
import shutil
import logging
import subprocess

import modules.utilities as utilities
from modules.utilities import chmodX
from subprocess import call, Popen, PIPE, STDOUT
from dateutil import parser as time_parser
from urllib.parse import urljoin,urlparse

from modules import Datastorer

stamp_build_syzkaller = "BUILD_SYZKALLER"
stamp_build_kernel = "BUILD_KERNEL"
stamp_reproduce_ori_poc = "REPRO_ORI_POC"

supports_compiler = {
    0: "gcc",
    1: "clang"
}

syz_config_template="""
{{
  "target": "linux/amd64/{8}",
  "http": "127.0.0.1:{5}",
  "workdir": "{0}/workdir",
  "kernel_obj": "{1}",
  "image": "{2}/stretch.img",
  "sshkey": "{2}/stretch.img.key",
  "syzkaller": "{0}",
  "procs": 8,
  "type": "qemu",
  "testcase": "{0}/workdir/testcase-{4}",
  "analyzer_dir": "{6}",
  "time_limit": "{7}",
  "store_read": {10},
  "vm": {{
    "count": {9},
    "kernel": "{1}/arch/x86/boot/bzImage",
    "cpu": 2,
    "mem": 2048
  }},
  "enable_syscalls" : [
    {3}
  ]
}}"""

class Deployer():
  def __init__(self, data, dst, index=0, force=False, max=-1, parallel_max=-1, port=53777, time=8, kernel_fuzzing=False, gdb_port=1235, qemu_monitor_port=9700, debug=False, logs=True):
    """
    deployer environment
    index: table中的第几个,默认是第0个,因为其他的还没有实现
    debug: 是否开启log
    force: 是否重新clone/build
    max: 编译时候使用的核心最多
    """
    if not isinstance(data, Datastorer):
      print("data format can't support!")
      exit(-1)

    self.data = data
    self.dst = dst

    # flags
    # logs all logs for only one
    self.debug = debug
    self.logs = logs

    """
    config file in one machine
    syzbuild_debug
    """
    self.config = None

    self.idx = index

    self.force= force
    self.image_switching_date = datetime.datetime(2020, 3, 15)
    self.catalog = 'incomplete'
    self.linux_addr = ""

    # TODO: 这里默认用nproc个核心去编译内核
    # self.max = max
    # if self.max <8 :
    #   self.max = 8
    self.max = -1

    self.init_logger(self.data.hash[:8])
    self.deploy()

  def init_logger(self, hash_val=None):
    self.logger = logging.getLogger(__name__)
    for each in self.logger.handlers:
      self.logger.removeHandler(each)
    handler = logging.StreamHandler(sys.stdout)
    if hash_val != None:
      format = logging.Formatter('%(asctime)s Thread: {} %(message)s'.format(hash_val))
    else:
      format = logging.Formatter('%(asctime)s Thread: %(message)s')
    handler.setFormatter(format)
    self.logger.addHandler(handler)
    if self.debug:
      self.logger.setLevel(logging.DEBUG)
      self.logger.propagate = True
    else:
      self.logger.setLevel(logging.INFO)
      self.logger.propagate = False

  def __check_stamp(self, name, hash_val, folder):
    stamp_path1 = "{}/work/{}/{}/.stamp/{}".format(self.project_path, folder, hash_val, name)
    return os.path.isfile(stamp_path1)

  def check_operation(self):
    with os.popen('cat /etc/os-release') as f:
      os_info = f.read()

    if 'Fedora' in os_info:
        return "fedora"
    elif 'Ubuntu' in os_info:
        return "ubuntu"
    elif 'Debian' in os_info:
        return "debian"
    else:
        return "unknown"

  def reproduced_ori_poc(self, hash_val, folder):
    return self.__check_stamp(stamp_reproduce_ori_poc, hash_val[:7], folder)

  # def init_crash_checker(self, port):
  #   self.crash_checker = CrashChecker(
  #       self.project_path,
  #       self.current_case_path,
  #       port,
  #       self.logger,
  #       self.debug,
  #       self.index,
  #       self.max_qemu_for_one_case,
  #       store_read=self.store_read,
  #       compiler=self.compiler,
  #       max_compiling_kernel=self.max_compiling_kernel)

  def __deploy_syzkaller_config(self, hash_val, case):
    self.project_path = os.getcwd()
    self.package_path = os.path.join(self.project_path)
    self.current_case_path = "{}/work/{}/{}".format(self.project_path, self.catalog, hash_val[:7])
    if self.dump:
      self.dump_path=self.current_case_path+"/dump"
    self.image_path = "{}/img".format(self.current_case_path)
    self.syzkaller_path = "{}/gopath/src/github.com/google/syzkaller".format(self.current_case_path)
    self.kernel_path = "{}/linux".format(self.current_case_path)
    if utilities.regx_match(r'386', case["manager"]):
      self.arch = "386"
    elif utilities.regx_match(r'amd64', case["manager"]):
      self.arch = "amd64"
    else:
      # TODO: 有些确实是其他架构的需要区别出来，一般人眼先看看
      # print("arch must be i386/amd64")
      self.arch = "amd64"

    self.logger.info(hash_val)

    self.compiler = utilities.set_compiler_version(time_parser.parse(case["time"]), case["config"])
    # impact_without_mutating = False
    self.__create_dir_for_case()
    if self.force:
      self.cleanup_built_kernel(hash_val)
      self.cleanup_built_syzkaller(hash_val)
    self.case_logger = self.__init_case_logger("{}-log".format(hash_val))
    self.case_info_logger = self.__init_case_logger("{}-info".format(hash_val))

    i386 = None
    if utilities.regx_match(r'386', case["manager"]):
      i386 = True

    # self.init_crash_checker(self.ssh_port)

    self.linux_addr = case['kernel']
    # TODO: 这里直接clone新的linux，不做复用
    self.linux_folder = self.kernel_path
    if os.path.exists(self.linux_folder):
      self.logger.info("linux cloned folder existed!\n")
    else:
      self.__run_linux_clone_script()

    r = self.__run_delopy_script(hash_val[:7], case)
    if r != 0:
      self.logger.error("Error occur in deploy.sh")
      self.__save_error(hash_val)
      return

    # TODO: CrashChecker和Kernel Fuzzing部分暂时不启用
    # self.__write_config(req.content.decode("utf-8"), hash_val[:7])
    # if self.kernel_fuzzing:
    #   title = None
    #   if not self.reproduced_ori_poc(hash_val, 'incomplete'):
    #     impact_without_mutating, title = self.do_reproducing_ori_poc(case, hash_val, i386)
    #   if not self.finished_fuzzing(hash_val, 'incomplete'):
    #     limitedMutation = True
    #     if 'patch' in case:
    #       limitedMutation = False
    #     exitcode = self.run_syzkaller(hash_val, limitedMutation)
    #     #self.remove_gopath(os.path.join(self.current_case_path, "poc"))
    #     is_error = self.save_case(hash_val, exitcode, case, limitedMutation, impact_without_mutating, title=title)
    #   else:
    #     self.logger.info("{} has finished fuzzing".format(hash_val[:7]))
    # elif self.reproduce_ori_bug:
    #   if not self.reproduced_ori_poc(hash_val, 'incomplete'):
    #     impact_without_mutating, title = self.do_reproducing_ori_poc(case, hash_val, i386)
    #     #self.remove_gopath(os.path.join(self.current_case_path, "poc"))
    #     is_error = self.save_case(hash_val, 0, case, False, impact_without_mutating, title=title)
    if self.dump:
      execprog_path = self.syzkaller_path+"/bin/linux_amd64/syz-execprog"
      executor_path = self.syzkaller_path+"/bin/linux_amd64/syz-executor"
      vmlinux_path = self.kernel_path+"/vmlinux"
      bzImage_path = self.kernel_path+"/arch/x86/boot/bzImage"

      os.makedirs(self.dump_path, exist_ok=True)

      shutil.copyfile(execprog_path, self.dump_path+"/syz-execprog")
      shutil.copyfile(executor_path, self.dump_path+"/syz-executor")
      shutil.copyfile(vmlinux_path, self.dump_path+"/vmlinux-"+case["commit"][:7])
      shutil.copyfile(bzImage_path, self.dump_path+"/bzImage-"+case["commit"][:7])

      if case['syz_repro']:
        req = requests.request(method='GET', url=case["syz_repro"])
        with open(self.dump_path+"/"+str(self.index)+".prog", "wb") as f:
          f.write(req.content)

      if case['c_repro']:
        req = requests.request(method='GET', url=case["c_repro"])
        with open(self.dump_path+"/"+str(self.index)+".c", "wb") as f:
          f.write(req.content)

      if case['log']:
        req = requests.request(method='GET', url=case["log"])
        with open(self.dump_path+"/log", "wb") as f:
          f.write(req.content)

      if case['report']:
        req = requests.request(method='GET', url=case["report"])
        with open(self.dump_path+"/report", "wb") as f:
          f.write(req.content)

      # succeed = 1

    # if succeed:
    #   self.__move_to_succeed(0)
    # elif is_error:
    #   self.__save_error(hash_val)
    # else:
    self.__move_to_completed()


  def compileTemplate(self):
    target = os.path.join(self.package_path, "scripts/syz-compile.sh")
    chmodX(target)
    self.logger.info("run: scripts/syz-compile.sh")
    p = Popen([target, self.current_case_path ,self.arch],
            stdout=PIPE,
            stderr=STDOUT
            )
    with p.stdout:
      self.__log_subprocess_output(p.stdout, logging.INFO)
    exitcode = p.wait()
    self.logger.info("script/syz-compile.sh is done with exitcode {}".format(exitcode))
    return exitcode == 0

  def correctTemplate(self):
    find_it = False
    pattern_type = utilities.SYSCALL
    text = ''
    pattern = ''
    try:
        path = os.path.join(self.syzkaller_path, 'CorrectTemplate')
        f = open(path, 'r')
        text = f.readline()
        if len(text) == 0:
            self.logger.info("Error: CorrectTemplate is empty")
            return find_it
    except:
        return find_it

    if text.find('syscall:') != -1:
        pattern = text.split(':')[1]
        pattern_type = utilities.SYSCALL
        pattern = pattern + "\("
    if text.find('arg:') != -1:
        pattern = text.split(':')[1]
        pattern_type = utilities.STRUCT
        i = pattern.find('[')
        if i != -1:
            pattern = "type " + pattern[:i]
        else:
            pattern = pattern + " {"

    search_path="sys/linux"
    extension=".txt"
    ori_syzkaller_path = os.path.join(self.current_case_path, "poc/gopath/src/github.com/google/syzkaller")
    regx_pattern = "^"+pattern
    src = os.path.join(ori_syzkaller_path, search_path)
    dst = os.path.join(self.syzkaller_path, search_path)
    find_it = self.syncFilesByPattern(regx_pattern, pattern_type, src, dst, extension)
    return find_it

  def syncFilesByPattern(self, pattern, pattern_type, src, dst, ends):
      find_it = False
      data = []
      target_file = ''
      brackets = -1 #-1 means no '{' found ever

      if not os.path.isdir(src):
          self.logger.info("{} do not exist".format(src))
          return find_it
      for file_name in os.listdir(src):
          if file_name.endswith(ends):
              find_it = False
              f = open(os.path.join(src, file_name), "r")
              text = f.readlines()
              f.close()
              for line in text:
                  if utilities.regx_match(pattern, line):
                      data.append(line)
                      find_it = True
                      if pattern_type == utilities.FUNC_DEF and line.find('{') != -1:
                          if brackets == -1:
                              brackets = 1
                      continue

                  if find_it:
                      if pattern_type == utilities.SYSCALL or (pattern_type == utilities.STRUCT and line == "\n"):
                          break
                      data.append(line)
                      if pattern_type == utilities.FUNC_DEF:
                          if line.find('{') != -1:
                              if brackets == -1:
                                  brackets = 0
                              brackets += 1
                          if line.find('}') != -1:
                              brackets -= 1
                          if brackets == 0:
                              break
              if find_it:
                  target_file = file_name
                  break

      if not os.path.isdir(dst):
          self.logger.info("{} do not exist".format(dst))
          return False
      for file_name in os.listdir(dst):
          if file_name.endswith(ends):
              #print(file_name)
              find_it = False
              start = 0
              end = 0
              f = open(os.path.join(dst, file_name), "r")
              text = f.readlines()
              f.close()
              for i in range(0, len(text)):
                  line = text[i]
                  if utilities.regx_match(pattern, line):
                      start = i
                      find_it = True
                      continue

                  if find_it:
                      end = i
                      if pattern_type == utilities.SYSCALL or (pattern_type == utilities.STRUCT and line == "\n"):
                          break

              if find_it:
                  f = open(os.path.join(dst, file_name), "w")
                  new_data = []
                  new_data.extend(text[:start])
                  new_data.extend(data)
                  new_data.extend(text[end:])
                  f.writelines(new_data)
                  f.close()
                  break
              elif target_file == file_name:
                  f = open(os.path.join(dst, file_name), "w")
                  new_data = []
                  new_data.extend(text)
                  new_data.extend(data)
                  f.writelines(new_data)
                  f.close()
                  find_it = True
                  break

      if pattern_type == utilities.SYSCALL:
          if utilities.regx_match(r'^syz_', pattern):
              regx_pattern = "^"+pattern
              src = os.path.join(self.current_case_path, "poc/gopath/src/github.com/google/syzkaller/executor")
              dst = os.path.join(self.syzkaller_path, "executor")
              file_ends = "common_linux.h"
              self.syncFilesByPattern(regx_pattern, utilities.FUNC_DEF, src, dst, file_ends)
      #if pattern_type == utilities.STRUCT:
      #    for each_struct in self.getSubStruct(data):
      #        self.replaceTemplate(each_struct, utilities.STRUCT)
      return find_it

  def getSubStruct(self, struct_data):
      regx_field = r'\W*([a-zA-Z0-9\[\]_]+)\W+([a-zA-Z0-9\[\]_, ]+)'
      start = False
      end = False
      res = []
      for line in struct_data:
          if line.find('{') != -1:
              start = True
          if line.find('}') != -1:
              end = True
          if end:
              break
          if start:
              field_type = utilities.regx_get(regx_field, line, 1)
              struct_list = self.extractStruct(field_type)
              if len(struct_list) > 0:
                  res.extend(struct_list)
      return res

  def extractStruct(self, text):
    trivial_type = ["int8", "int16", "int32", "int64", "int16be", "int32be", "int64be", "intptr",
                    "in", "out", "inout", "dec", "hex", "oct", "fmt", "string", "target",
                    "x86_real", "x86_16", "x86_32", "x86_64", "arm64", "text", "proc", "ptr", "ptr64",
                    "inet", "pseudo", "csum", "vma", "vma64", "flags", "const", "array", "void"
                    "len", "bytesize", "bytesize2", "bytesize4", "bytesize8", "bitsize", "offsetof"]

  def confirmSuccess(self, hash_val, case, limitedMutation=False):
      syz_repro = case["syz_repro"]
      syz_commit = case["syzkaller"]
      commit = case["commit"]
      config = case["config"]
      c_repro = case["c_repro"]
      i386 = None
      if utilities.regx_match(r'386', case["manager"]):
          i386 = True
      log = case["log"]
      res = []
      if not self.__check_confirmed(hash_val):
          """self.logger.info("Compare with original PoC")
          res = self.crash_checker.run(syz_repro, syz_commit, log, commit, config, c_repro, i386)
          if res[0]:
              n = self.crash_checker.diff_testcase(res[1], syz_repro)
              self.crash_checker.logger.info("difference of characters of two testcase: {}".format(n))
              self.crash_checker.logger.info("successful crash: {}".format(res[1]))
              read_before_write = self.crash_checker.check_read_before_write(res[1])
              if read_before_write:
                  self.crash_checker.logger.info("Detect read before write")
              self.logger.info("Write to confirmedSuccess")
              self.__write_to_confirmed_sucess(hash_val)
              path = res[1]
          else:
              self.crash_checker.logger.info("Call trace match failed")
          """
          res = self.repro_on_fixed_kernel(hash_val, case, limitedMutation=limitedMutation)
          """
          if res != []:
              self.logger.info("Write to confirmedSuccess")
              self.__write_to_confirmed_sucess(hash_val)
          """
          res = self.deduplicate_ori(res, syz_repro)
          return res
      return []

  def deduplicate_ori(self, paths, ori_prog):
    res = []
    for each in paths:
      prog = os.path.join(each, "repro.prog")
      if not os.path.exists(prog):
        continue
      f = open(prog, "r")
      text = f.readlines()
      prog_text1 = self.__distill_testcase(''.join(text))
      req = utilities.request_get(ori_prog)
      text = req.text
      prog_text2 = self.__distill_testcase(''.join(text))
      if prog_text1 == prog_text2:
        continue
      res.append(each)
    return res

  def repro_on_fixed_kernel(self, hash_val, case, crashes_path=None, limitedMutation=False):
    syz_repro = case["syz_repro"]
    syz_commit = case["syzkaller"]
    commit = case["commit"]
    config = case["config"]
    c_repro = case["c_repro"]
    i386 = None
    res = []
    if utilities.regx_match(r'386', case["manager"]):
      i386 = True
    commit = utilities.get_patch_commit(hash_val)
    if commit != None:
      res = self.crash_checker.repro_on_fixed_kernel(syz_commit, case["commit"], config, c_repro, i386, commit, crashes_path=crashes_path, limitedMutation=limitedMutation)
    return res

  def save_case(self, hash_val, exitcode, case, limitedMutation, impact_without_mutating, title=None, secondary_fuzzing=False):
    return self.__save_case(hash_val=hash_val, exitcode=exitcode, case=case, limitedMutation=limitedMutation, impact_without_mutating=impact_without_mutating, title=title, secondary_fuzzing=secondary_fuzzing)

  def __check_confirmed(self, hash_val):
    return False

  def __run_linux_clone_script(self):
    chmodX("scripts/linux-clone.sh")
    self.logger.info("run: scripts/linux-clone.sh {} {}".format(self.linux_addr, self.kernel_path))
    call(["scripts/linux-clone.sh", self.linux_addr, self.kernel_path])

  def __delopy_script(self, hash_val, case):
    commit = case["commit"]
    syzkaller = case["syzkaller"]
    config = case["config"]
    testcase = case["syz_repro"]
    if not testcase:
      testcase = ""
    time = case["time"]
    self.case_info_logger.info("\ncommit: {}\nsyzkaller: {}\nconfig: {}\ntestcase: {}\ntime: {}\narch: {}".format(commit,syzkaller,config,testcase,time,self.arch))

    case_time = time_parser.parse(time)
    if self.image_switching_date <= case_time:
      image = "stretch"
    else:
      image = "wheezy"
    target = os.path.join(self.package_path, "scripts/deploy.sh")
    chmodX(target)
    self.logger.info("run: scripts/deploy.sh")
    p = Popen([target,
               self.linux_folder,
               hash_val,
               commit,
               syzkaller,
               config,
               self.catalog,
               image,
               self.arch,
               self.compiler,
               str(self.max)
              ],
              stdout=PIPE,
              stderr=STDOUT
              )
    with p.stdout:
      self.__log_subprocess_output(p.stdout, logging.INFO)
    exitcode = p.wait()
    self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
    return exitcode

  def __deploy_syzkaller_config(self, testcase, hash_val):
    dependent_syscalls = []
    syscalls = self.__extract_syscalls(testcase)
    if syscalls == []:
      self.logger.info("No syscalls found in testcase: {}".format(testcase))
      return -1
    for each in syscalls:
      dependent_syscalls.extend(self.__extract_dependent_syscalls(each, self.syzkaller_path))
    if len(dependent_syscalls) < 1:
      self.logger.info("Cannot find dependent syscalls for\n{}\nTry to continue without them".format(testcase))
    new_syscalls = syscalls.copy()
    new_syscalls.extend(dependent_syscalls)
    new_syscalls = utilities.unique(new_syscalls)
    enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""
    syz_config = syz_config_template.format(self.syzkaller_path,
                                            self.kernel_path,
                                            self.image_path,
                                            enable_syscalls,
                                            hash_val,
                                            self.ssh_port,
                                            self.current_case_path,
                                            self.time_limit,
                                            self.arch,
                                            self.max_qemu_for_one_case,
                                            str(self.store_read).lower()
                                            )
    f = open(os.path.join(self.syzkaller_path, "workdir/{}-poc.cfg".format(hash_val)), "w")
    f.writelines(syz_config)
    f.close()

    #Add more syscalls
    new_added_syscalls = []
    for i in range(0, min(2,len(syscalls))):
      if syscalls[len(syscalls)-1-i] not in new_added_syscalls:
        new_added_syscalls.extend(self.__extract_all_syscalls(syscalls[len(syscalls)-1-i], self.syzkaller_path))
    raw_syscalls = self.__extract_raw_syscall(new_added_syscalls)
    new_syscalls = syscalls.copy()
    new_syscalls.extend(raw_syscalls)
    new_syscalls = utilities.unique(new_syscalls)
    enable_syscalls = "\"" + "\",\n\t\"".join(new_syscalls) + "\""
    syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash_val, self.ssh_port, self.current_case_path, self.time_limit, self.arch, self.max_qemu_for_one_case, str(self.store_read).lower())
    f = open(os.path.join(self.syzkaller_path, "workdir/{}.cfg".format(hash_val)), "w")
    f.writelines(syz_config)
    f.close()

  def __extract_syscalls(self, testcase):
    res = []
    text = testcase.split('\n')
    for line in text:
      if len(line)==0 or line[0] == '#':
        continue
      m = re.search(r'(\w+(\$\w+)?)\(', line)
      if m == None or len(m.groups()) == 0:
        self.logger.info("Failed to extract syscall from {}".format(self.index, line))
        return res
      syscall = m.groups()[0]
      res.append(syscall)
    return res

  def __extract_dependent_syscalls(self, syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
    res = []
    dir = os.path.join(syzkaller_path, search_path)
    if not os.path.isdir(dir):
      self.logger.info("{} do not exist".format(dir))
      return res
    for file in os.listdir(dir):
      if file.endswith(extension):
        find_it = False
        f = open(os.path.join(dir, file), "r")
        text = f.readlines()
        f.close()
        line_index = 0
        for line in text:
          if line.find(syscall) != -1:
            find_it = True
            break
          line_index += 1

        if find_it:
          upper_bound = 0
          lower_bound = 0
          for i in range(0, len(text)):
            if line_index+i<len(text):
              line = text[line_index+i]
              if utilities.regx_match(r'^\n', line):
                upper_bound = 1
              if upper_bound == 0:
                m = re.match(r'(\w+(\$\w+)?)\(', line)
                if m != None and len(m.groups()) > 0:
                  call = m.groups()[0]
                  res.append(call)
            else:
              upper_bound = 1

            if line_index-i>=0:
              line = text[line_index-i]
              if utilities.regx_match(r'^\n', line):
                lower_bound = 1
              if lower_bound == 0:
                m = re.match(r'(\w+(\$\w+)?)\(', line)
                if m != None and len(m.groups()) > 0:
                  call = m.groups()[0]
                  res.append(call)
            else:
              lower_bound = 1

            if upper_bound and lower_bound:
              return res
    return res

  def __extract_all_syscalls(self, last_syscall, syzkaller_path, search_path="sys/linux", extension=".txt"):
      res = []
      dir = os.path.join(syzkaller_path, search_path)
      if not os.path.isdir(dir):
          self.logger.info("{} do not exist".format(dir))
          return res
      for file in os.listdir(dir):
        if file.endswith(extension):
            find_it = False
            f = open(os.path.join(dir, file), "r")
            text = f.readlines()
            f.close()
            for line in text:
                if line.find(last_syscall) != -1:
                    find_it = True
                    break

            if find_it:
                for line in text:
                    m = re.match(r'(\w+(\$\w+)?)\(', line)
                    if m == None or len(m.groups()) == 0:
                        continue
                    syscall = m.groups()[0]
                    res.append(syscall)
                break
      return res

  def __extract_raw_syscall(self, syscalls):
    res = []
    for call in syscalls:
      m = re.match(r'((\w+)(\$\w+)?)', call)
      if m == None or len(m.groups()) == 0:
        continue
      syscall = m.groups()[1]
      if syscall not in res:
        res.append(syscall)
    return res

  def __save_case(self, hash_val, exitcode, case, limitedMutation, impact_without_mutating, title=None, secondary_fuzzing=False):
      self.__copy_crashes()
      self.create_finished_fuzzing_stamp()
      new_impact_type = self.__new_impact(hash_val[:7])
      if new_impact_type != utilities.NONCRITICAL:
              paths = self.confirmSuccess(hash_val, case, limitedMutation)
              if len(paths) > 0:
                  if impact_without_mutating:
                      self.copy_new_impact(case, impact_without_mutating, title)
                  for each in paths:
                      self.copy_new_impact(each, False, title)
                      self.write_to_confirm(hash_val, new_impact_type)
                  #self.__move_to_succeed(new_impact_type)
              elif impact_without_mutating:
                  self.copy_new_impact(case, impact_without_mutating, title)
                  self.write_to_confirm(hash_val, new_impact_type)
                  #self.__move_to_succeed(new_impact_type)
              else:
                  if exitcode !=0:
                      return 1
      elif impact_without_mutating:
          self.copy_new_impact(case, impact_without_mutating, title)
          #self.__move_to_succeed(new_impact_type)
      return 0

  def copy_new_impact(self, path, impact_without_mutating, title):
      output = os.path.join(self.current_case_path, "output")
      os.makedirs(output, exist_ok=True)
      if impact_without_mutating:
          ori = os.path.join(output, "ori")
          os.makedirs(ori, exist_ok=True)
          case = path
          if case['syz_repro'] != None:
              r = utilities.request_get(case['syz_repro'])
              with open(os.path.join(ori, "repro.prog"), "w") as f:
                  f.write(r.text)
          if case['c_repro'] != None:
              r = utilities.request_get(case['c_repro'])
              with open(os.path.join(ori, "repro.cprog"), "w") as f:
                  f.write(r.text)
          crash_log = "{}/{}".format(self.current_case_path, "poc/crash_log-ori")
          if os.path.isfile(crash_log):
              repro_log = os.path.join(ori, "repro.log")
              self.copy_only_impact(crash_log, repro_log)
              self.generate_decent_report(repro_log, os.path.join(ori, "repro.report"))
          with open(os.path.join(ori, "description"), "w") as f:
                  f.write(title)
      else:
          if path == None:
              self.logger.error("Error: crash path is None")
              return
          src_files = os.listdir(path)
          base = os.path.basename(path)
          for files in src_files:
              if files == "description":
                  with open(os.path.join(path, files), "r") as f:
                      line = f.readline()
                      for alert_key in self.alert:
                          if len(alert_key) > 0 and utilities.regx_match(alert_key, line):
                              self.__trigger_alert(base, alert_key)
          dst = os.path.join(output, base)
          if os.path.exists(dst):
              shutil.rmtree(dst)
          shutil.copytree(path, dst)

  def __trigger_alert(self, name, alert_key):
      self.logger.info("An alert for {} was trigger by crash {}".format(alert_key, name))

  def __save_error(self, hash_val):
      self.logger.info("case {} encounter an error. See log for details.".format(hash_val))
      self.__move_to_error()

  def __copy_crashes(self):
      crash_path = "{}/workdir/crashes".format(self.syzkaller_path)
      dest_path = "{}/crashes".format(self.current_case_path)
      i = 0
      if os.path.isdir(crash_path) and len(os.listdir(crash_path)) > 0:
          while(1):
              try:
                  shutil.copytree(crash_path, dest_path)
                  self.logger.info("Found crashes, copy them to {}".format(dest_path))
                  break
              except FileExistsError:
                  dest_path = "{}/crashes-{}".format(self.current_case_path, i)
                  i += 1

  def __move_to_completed(self):
    self.logger.info("Copy to completed")
    src = self.current_case_path
    base = os.path.basename(src)
    completed = "{}/work/completed".format(self.project_path)
    des = "{}/{}".format(completed, base)
    if not os.path.isdir(completed):
      os.makedirs(completed, exist_ok=True)
    if src == des:
      return
    if os.path.isdir(des):
      try:
        os.rmdir(des)
      except:
        self.logger.info("Fail to delete directory {}".format(des))
    shutil.move(src, des)
    self.current_case_path = des

  def __move_to_succeed(self, new_impact_type):
    self.logger.info("Copy to succeed")
    src = self.current_case_path
    base = os.path.basename(src)
    succeed = "{}/work/succeed".format(self.project_path)
    des = "{}/{}".format(succeed, base)
    if not os.path.isdir(succeed):
      os.makedirs(succeed, exist_ok=True)
    if src == des:
      return
    if os.path.isdir(des):
      try:
        os.rmdir(des)
      except:
        self.logger.info("Fail to delete directory {}".format(des))
    shutil.move(src, des)
    self.current_case_path = des

  def __move_to_error(self):
    self.logger.info("Copy to error")
    src = self.current_case_path
    base = os.path.basename(src)
    error = "{}/work/error".format(self.project_path)
    des = "{}/{}".format(error, base)
    if not os.path.isdir(error):
      os.makedirs(error, exist_ok=True)
    if src == des:
      return
    if os.path.isdir(des):
      os.rmdir(des)
    shutil.move(src, des)
    self.current_case_path = des

  def __create_dir_for_case(self):
    res, succeed = self.__copy_from_duplicated_cases()
    if res:
      return succeed
    path = "{}/.stamp".format(self.current_case_path)
    if not os.path.isdir(path):
      os.makedirs(path, exist_ok=True)
    return succeed

  def __copy_from_duplicated_cases(self):
    des = self.current_case_path
    base = os.path.basename(des)
    for dirs in ["completed", "incomplete", "error", "succeed"]:
      src = "{}/work/{}/{}".format(self.project_path, dirs, base)
      if src == des:
        continue
      if os.path.isdir(src):
        try:
          shutil.move(src, des)
          self.logger.info("Found duplicated case in {}".format(src))
          return True, dirs == "succeed"
        except:
          self.logger.info("Fail to copy the duplicated case from {}".format(src))
    return False, False

  def __get_default_log_format(self):
      return logging.Formatter('%(asctime)s %(levelname)s  %(message)s')

  def __init_case_logger(self, logger_name):
      handler = logging.FileHandler("{}/log".format(self.current_case_path))
      format = logging.Formatter('%(asctime)s %(message)s')
      handler.setFormatter(format)
      logger = logging.getLogger(logger_name)
      logger.setLevel(self.logger.level)
      logger.addHandler(handler)
      logger.propagate = False
      if self.debug:
          logger.propagate = True
      return logger

  def __log_subprocess_output(self, pipe, log_level):
      for line in iter(pipe.readline, b''):
          if log_level == logging.INFO:
              self.case_logger.info(line)
          if log_level == logging.DEBUG:
              self.case_logger.debug(line)

  def __new_impact(self, hash_val):
      hash_val = hash_val[:7]
      ret = utilities.NONCRITICAL
      if self.__success_check(hash_val, "AbnormallyMemRead") and self.store_read:
          ret |= utilities.AbMemRead
      if self.__success_check(hash_val, "AbnormallyMemWrite"):
          ret |= utilities.AbMemWrite
      if self.__success_check(hash_val, "DoubleFree"):
          ret |= utilities.InvFree
      return ret

  def __success_check(self, hash_val, name):
      hash_val = hash_val[:7]
      success_path = "{}/work/{}".format(self.project_path, name)
      if os.path.isfile(success_path):
          f = open(success_path, "r")
          text = f.readlines()
          f.close()
          for line in text:
              line = line.strip('\n')
              if line == hash_val:
                  return True
      return False

  def __need_kasan_patch(self, title):
    return utilities.regx_match(r'slab-out-of-bounds Read', title)

  def __distill_testcase(self, text):
      res = ''
      text = text.split('\n')
      for i in range(0, len(text)):
          line = text[i]
          if line[0] == "#":
              continue
          res = ''.join(text[i:])
          break
      return res

  # chose one
  def deploy(self):
    LINUX = ""
    SYZKALLER = ""
    if self.data.cases[self.idx]['kernel'] == "upstream":
      try:
        LINUX = os.environ['LINUX']
      except KeyError:
        LINUX = input("please set upstream linux path:\n")

    try:
      SYZKALLER = os.environ['SYZKALLER']
    except KeyError:
      SYZKALLER = input("please set upstream syzkaller path:\n")

    # TODO: judge the compiler version and get the compiler path
    compiler = 0
    if self.data.cases[self.idx]['gcc']:
      compiler = 0
    elif self.data.cases[self.idx]['clang']:
      compiler = 1
    else:
      print("failed to find compiler")
      exit(-1)

    if not compiler:
      find = supports_compiler[0].upper()+ self.data.cases[self.idx]['version']
      GCC = os.environ.get(find)
    else:
      find = supports_compiler[1].upper()+ self.data.cases[self.idx]['version']
      CLANG = os.environ.get(clang)


    # GCC8 = os.environ.get("GCC8")
    # GCC9 = os.environ.get("GCC9")
    # GCC10 = os.environ.get("GCC10")
    # GCC11 = os.environ.get("GCC11")
    # GCC12 = os.environ.get("GCC12")
    # CLANG8 = os.environ.get("CLANG8")
    # CLANG9 = os.environ.get("CLANG9")
    # CLANG10 = os.environ.get("CLANG10")
    # CLANG11 = os.environ.get("CLANG11")
    # CLANG12 = os.environ.get("CLANG12")
    # CLANG13 = os.environ.get("CLANG13")
    # CLANG14 = os.environ.get("CLANG14")
    # CLANG15 = os.environ.get("CLANG15")
    # CLANG16 = os.environ.get("CLANG16")
    # CLANG17 = os.environ.get("CLANG17")

    PATCH = os.environ.get("PATCH")
    if PATCH:
      # TODO: choice the patch path
      pass

    with open(os.path.join(self.dst, "description"), "w") as fp:
      fp.write(self.data.title)

    with open(os.path.join(self.dst, "url"), "w") as fp:
      fp.write(self.data.url)

    # deploying
    # import ipdb; ipdb.set_trace();
    os.chdir(self.dst)
    self.__deploy_kernel(default=LINUX)
    self.__deploy_patch(default=PATCH)

    self.__compile_kernel()
    self.__deploy_syzkaller(default=SYZKALLER)

    if not compiler:
      self.__deploy_gcc(default=GCC)
    else:
      self.__deploy_clang(default=CLANG)
    self.__deploy_report()

    self.__deploy_disk()

    if self.logs_flag:
      self._deploy_all_logs()
    else:
      self._deploy_log()

  def deploy_allcases(self):
    print("not implemented now")

  def __deploy_kernel(self, default=""):
    """
    default: the path of existed upstream linux for saving time
    """
    if not default:
      print("maybe not UPSTREAM_LINUX.")

    if self.data.cases[self.idx]['kernel'] == "upstream":
      kernel = default
      if not os.path.exists(kernel):
        print('defalut kernel folder do not existed!')
        exit(-1)

      try:
        res = subprocess.run(["cp", "-r", "{}".format(kernel),"{}".format(os.path.join(self.dst, "kernel"))],
                             check=True,
                             text=True,
                             capture_output=True)
        # 访问返回码
        # returncode = res.returncode
        # print(f"返回码：{returncode}")

        # 访问标准输出和标准错误
        # stdout = res.stdout
        # stderr = res.stderr
        # print(f"标准输出：{stdout}")
        # print(f"标准错误：{stderr}")

      except subprocess.CalledProcessError as e:
        print("subprocess failed ", e)
        exit(-1)

      if self.dst is not None:
        req = requests.request(method='GET', url=self.data.cases[self.idx]['config'])
        kernel = os.path.join(self.dst, "kernel")
        with open(os.path.join(kernel, '.config'), 'wb') as fd:
          fd.write(req.text.encode())

      os.chdir(os.path.join(self.dst, "kernel"))
      os.system("git checkout -q " + self.data.cases[self.idx]['commit'])
    elif self.data.cases[self.idx]['kernel'] == "net-next":
      # git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git/snapshot/net-next-55c900477f5b3897d9038446f72a281cae0efd86.tar.gz
      snapshot = "https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git/snapshot/"
      commit = urlparse(self.data.cases[self.idx]['commit']).query.strip("id=")
      url = urljoin(snapshot, "net-next-"+commit+".tar.gz")
      print(url)
    elif self.data.cases[self.idx]['kernel'] == "linux-next":
      # git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/snapshot/linux-next-715abedee4cd660ad390659aefa7482f05275bbd.tar.gz
      snapshot = "https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/snapshot/"
      commit = urlparse(self.data.cases[self.idx]['commit']).query.strip("id=")
      url = urljoin(snapshot, "linux-next-"+commit+".tar.gz")
    else:
      print("not implemented now, do not support this kernel.")
      exit(-1)

    kernel_dst = os.path.join(self.dst, "kernel.tar.gz")
    # with open(os.path.join(self.dst, "kernel.tar.gz"), 'wb') as fd:
    if os.path.exists(kernel_dst):
      co = input("kernel.tar.gz existed. Redownloading? (y/n) ?\n")
      if co == "y":
        self.__download_file(url, kernel_dst)
    else:
      self.__download_file(url, kernel_dst)
    # whatever extract it
    try:
      os.mkdir(os.path.join(self.dst, "kernel"))
    except FileExistsError:
      pass

    import ipdb; ipdb.set_trace()
    ignore = os.system("tar xvf kernel.tar.gz -C kernel")
    if ignore:
      print('please check kernel.tar.gz')
      exit(-1)

  def __compile_kernel(self):
    pass

  def __download_file(self, url, dst):
    from tqdm import tqdm
    with requests.get(url, stream=True) as r:
      r.raise_for_status()
      total_size_in_bytes = int(r.headers.get('content-length', 0))
      block_size = 1024 # 1 Kibibyte
      progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True)
      with open(dst, 'wb') as file:
        for data in r.iter_content(block_size):
          progress_bar.update(len(data))
          file.write(data)
      progress_bar.close()

  def __deploy_syzkaller(self, default=""):
      if not default:
          print("please set UPSTREAM_SYZKALLER.")
          exit(-1)
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
      os.system("git checkout -q " + self.data.cases[self.idx]['syzkaller'])

  def __deploy_gcc(self):
      """
      gcc (Debian 12.2.0-14) 12.2.0
      gcc (Debian 10.2.1-6) 10.2.1 20210110
      Debian clang version 11.0.1-2
      """
      gcc = self.data.cases[self.idx]['gcc']
      if gcc == "gcc (Debian 12.2.0-14) 12.2.0":
          print("gcc12")
      else:
          print("not implemented now")

  def __deploy_clang(self):
      """
      fuck
      """
      pass

  def __deploy_report(self):
      req = requests.request(method='GET', url=self.data.cases[self.idx]['report'])
      with open(os.path.join(self.dst, 'report'), "wb")as fd:
          fd.write(req.text.encode())

      syzkaller = os.path.join(os.path.dirname(self.dst), "syzkaller")

  def __deploy_log(self):
      req = requests.request(method='GET', url=self.data.cases[self.idx]['log'])
      with open(os.path.join(self.dst, 'log'), "wb") as fd:
          fd.write(req.text.encode())

  def __deploy_all_logs(self):
      for self.idx, case in self.data.cases.items():
          req = requests.request(method='GET', url=case['log'])
          with open(os.path.join(self.dst, 'log{}'.format(self.idx)), "wb") as fd:
              fd.write(req.text.encode())

  def __deploy_disk(self, default=""):
    # os.system()
    pass

