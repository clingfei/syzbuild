from math import trunc
import re
import os
import sys
import requests
import datetime
import shutil
import logging

import modules.utilities as utilities
from modules.utilities import chmodX
from modules.crawler import syzbot_host_url, syzbot_bug_base_url
from subprocess import call, Popen, PIPE, STDOUT
from dateutil import parser as time_parser

import ipdb

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
  def __init__(self, index=0, debug=False, force=False):
    self.index= index
    self.debug = debug
    self.force= force
    self.image_switching_date = datetime.datetime(2020, 3, 15)
    self.catalog = 'incomplete'
    self.linux_addr = ""
    # TODO: 这里默认用8个核心去编译内核
    self.max_compiling_kernel = 8

  def init_logger(self, debug, hash_val=None):
    self.logger = logging.getLogger(__name__+str(self.index))
    for each in self.logger.handlers:
      self.logger.removeHandler(each)
    handler = logging.StreamHandler(sys.stdout)
    if hash_val != None:
      format = logging.Formatter('%(asctime)s Thread {}: {} %(message)s'.format(self.index, hash_val))
    else:
      format = logging.Formatter('%(asctime)s Thread {}: %(message)s'.format(self.index))
    handler.setFormatter(format)
    self.logger.addHandler(handler)
    if debug:
      self.logger.setLevel(logging.DEBUG)
      self.logger.propagate = True
    else:
      self.logger.setLevel(logging.INFO)
      self.logger.propagate = False
  
  def setup_hash(self, hash_val):
    self.hash_val = hash_val
    self.init_logger(self.debug, self.hash_val[:7])

  def deploy(self, hash_val, case):
    self.setup_hash(hash_val)
    self.project_path = os.getcwd()
    self.package_path = os.path.join(self.project_path)
    self.current_case_path = "{}/work/{}/{}".format(self.project_path, self.catalog, hash_val[:7])
    self.image_path = "{}/img".format(self.current_case_path)
    self.syzkaller_path = "{}/gopath/src/github.com/google/syzkaller".format(self.current_case_path)
    self.kernel_path = "{}/linux".format(self.current_case_path)
    if utilities.regx_match(r'386', case["manager"]):
      self.arch = "386"
    elif utilities.regx_match(r'amd64', case["manager"]):
      self.arch = "amd64"
    else:
      print("arch must be i386/amd64")
      self.arch = "amd64"
      # TODO: 有些确实是其他架构的需要区别出来，不过一般人眼先看看
      # exit(-1)

    self.logger.info(hash_val)

    self.compiler = utilities.set_compiler_version(time_parser.parse(case["time"]), case["config"])
    impact_without_mutating = False
    succeed = self.__create_dir_for_case()
    if self.force:
      self.cleanup_built_kernel(hash_val)
      self.cleanup_built_syzkaller(hash_val)
    self.case_logger = self.__init_case_logger("{}-log".format(hash_val))
    self.case_info_logger = self.__init_case_logger("{}-info".format(hash_val))

    # url = syzbot_host_url + syzbot_bug_base_url + hash_val
    # self.case_info_logger.info(url)
    # self.case_info_logger.info("pid: {}".format(os.getpid()))

    i386 = None
    if utilities.regx_match(r'386', case["manager"]):
      i386 = True
    
    self.linux_addr = case['kernel']
    # TODO: 这里直接clone新的linux，不做复用
    self.linux_folder = self.kernel_path
    if os.path.exists(self.linux_folder):
      print("linux cloned folder existed!\n") 
    else:
      self.clone_linux()

    r = self.__run_delopy_script(hash_val[:7], case)
    if r != 0:
      self.logger.error("Error occur in deploy.sh")
      self.__save_error(hash_val)
      return

    req = requests.request(method='GET', url=case["syz_repro"])
    is_error = 0
    self.__write_config(req.content.decode("utf-8"), hash_val[:7])
    if self.kernel_fuzzing:
      title = None
      if not self.reproduced_ori_poc(hash_val, 'incomplete'):
        impact_without_mutating, title = self.do_reproducing_ori_poc(case, hash_val, i386)
      if not self.finished_fuzzing(hash_val, 'incomplete'):
        limitedMutation = True
        if 'patch' in case:
          limitedMutation = False
        exitcode = self.run_syzkaller(hash_val, limitedMutation)
        #self.remove_gopath(os.path.join(self.current_case_path, "poc"))
        is_error = self.save_case(hash_val, exitcode, case, limitedMutation, impact_without_mutating, title=title)
      else:
        self.logger.info("{} has finished fuzzing".format(hash_val[:7]))
    elif self.reproduce_ori_bug:
      if not self.reproduced_ori_poc(hash_val, 'incomplete'):
        impact_without_mutating, title = self.do_reproducing_ori_poc(case, hash_val, i386)
        #self.remove_gopath(os.path.join(self.current_case_path, "poc"))
        is_error = self.save_case(hash_val, 0, case, False, impact_without_mutating, title=title)

    if succeed:
      self.__move_to_succeed(0)
    elif is_error:
      self.__save_error(hash_val)
    else:
      self.__move_to_completed()
    
    return self.index

  def clone_linux(self):
    self.__run_linux_clone_script()

  def run_syzkaller(self, hash_val, limitedMutation):
    self.logger.info("run syzkaller".format(self.index))
    syzkaller = os.path.join(self.syzkaller_path, "bin/syz-manager")
    exitcode = 4
    # First round, we only enable limited syscalls.
    # If failed to trigger a write crash, we enable more syscalls to run it again
    for _ in range(0, 3):
      if self.logger.level == logging.DEBUG:
          p = Popen([syzkaller, "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash_val[:7]), "-debug", "-poc"],
              stdout=PIPE,
              stderr=STDOUT
              )
          with p.stdout:
              self.__log_subprocess_output(p.stdout, logging.INFO)
          exitcode = p.wait()

          if not limitedMutation:
              p = Popen([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash_val[:7]), "-debug"],
                  stdout=PIPE,
                  stderr=STDOUT
                  )
              with p.stdout:
                  self.__log_subprocess_output(p.stdout, logging.INFO)
          exitcode = p.wait()
      else:
          p = Popen([syzkaller, "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash_val[:7]), "-poc"],
              stdout = PIPE,
              stderr = STDOUT
              )
          with p.stdout:
              self.__log_subprocess_output(p.stdout, logging.INFO)
          exitcode = p.wait()

          if not limitedMutation:
              p = Popen([syzkaller, "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash_val[:7])],
                  stdout = PIPE,
                  stderr = STDOUT
                  )
              with p.stdout:
                  self.__log_subprocess_output(p.stdout, logging.INFO)
          exitcode = p.wait()
      if exitcode != 4:
          break
    self.logger.info("syzkaller is done with exitcode {}".format(exitcode))
    if exitcode == 3:
      #Failed to parse the testcase
      if self.correctTemplate() and self.compileTemplate():
        exitcode = self.run_syzkaller(hash_val, limitedMutation)
    return exitcode
  
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

  def __run_delopy_script(self, hash_val, case):
    ipdb.set_trace()
    commit = case["commit"]
    syzkaller = case["syzkaller"]
    config = case["config"]
    testcase = case["syz_repro"]
    time = case["time"]
    self.case_info_logger.info("\ncommit: {}\nsyzkaller: {}\nconfig: {}\ntestcase: {}\ntime: {}\narch: {}".format(commit,syzkaller,config,testcase,time,self.arch))

    case_time = time_parser.parse(time)
    if self.image_switching_date <= case_time:
      image = "stretch"
    else:
      image = "wheezy"
    target = os.path.join(self.package_path, "scripts/deploy.sh")
    chmodX(target)
    index = str(self.index)
    self.logger.info("run: scripts/deploy.sh")
    # print([target, 
    #            self.linux_folder, 
    #            hash_val, 
    #            commit, 
    #            syzkaller, 
    #            config, 
    #            testcase, 
    #            index, 
    #            self.catalog, 
    #            image, 
    #            self.arch, 
    #            self.compiler, 
    #            str(self.max_compiling_kernel)
    #           ])
    p = Popen([target, 
               self.linux_folder, 
               hash_val, 
               commit, 
               syzkaller, 
               config, 
               testcase, 
               index, 
               self.catalog, 
               image, 
               self.arch, 
               self.compiler, 
               str(self.max_compiling_kernel)
              ],
              stdout=PIPE,
              stderr=STDOUT
              )
    with p.stdout:
      self.__log_subprocess_output(p.stdout, logging.INFO)
    exitcode = p.wait()
    self.logger.info("script/deploy.sh is done with exitcode {}".format(exitcode))
    return exitcode

  def __write_config(self, testcase, hash_val):
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
    syz_config = syz_config_template.format(self.syzkaller_path, self.kernel_path, self.image_path, enable_syscalls, hash_val, self.ssh_port, self.current_case_path, self.time_limit, self.arch, self.max_qemu_for_one_case, str(self.store_read).lower())
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
      return logging.Formatter('%(asctime)s %(levelname)s [{}] %(message)s'.format(self.index))

  def __init_case_logger(self, logger_name):
      handler = logging.FileHandler("{}/log".format(self.current_case_path))
      format = logging.Formatter('%(asctime)s [{}] %(message)s'.format(self.index))
      handler.setFormatter(format)
      logger = logging.getLogger(logger_name)
      logger.setLevel(self.logger.level)
      logger.addHandler(handler)
      logger.propagate = False
      if self.debug:
          logger.propagate = True
      return logger
  
  def __init_case_info_logger(self, logger_name):
      handler = logging.FileHandler("{}/info".format(self.current_case_path))
      format = self.__get_default_log_format()
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
