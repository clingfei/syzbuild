import re
import os, stat, sys
import requests
import threading
import logging
import time
import shutil
import modules.utilities as utilities
from modules.utilities import chmodX

from modules.crawler import syzbot_host_url, syzbot_bug_base_url
from subprocess import call, Popen, PIPE, STDOUT
from dateutil import parser as time_parser
from .case import Case, stamp_build_kernel, stamp_build_syzkaller, stamp_finish_fuzzing, stamp_reproduce_ori_poc, stamp_symbolic_execution, stamp_static_analysis

TIMEOUT_DYNAMIC_VALIDATION=60*60
TIMEOUT_STATIC_ANALYSIS=60*30

class Workers(Case):
    def __init__(self, index, parallel_max, debug=False, force=False, port=53777, replay='incomplete', linux_index=-1, time=8, kernel_fuzzing=False, reproduce=False, alert=[], static_analysis=False, symbolic_execution=False, gdb_port=1235, qemu_monitor_port=9700, max_compiling_kernel=-1, timeout_dynamic_validation=None, timeout_static_analysis=None, timeout_symbolic_execution=None, guided=False, be_bully=False, se_poc=None):
        Case.__init__(self, index, parallel_max, debug, force, port, replay, linux_index, time, kernel_fuzzing, reproduce, alert, static_analysis, symbolic_execution, gdb_port, qemu_monitor_port, max_compiling_kernel)
        if timeout_dynamic_validation == None:
            self.timeout_dynamic_validation=TIMEOUT_DYNAMIC_VALIDATION
        else:
            self.timeout_dynamic_validation=int(timeout_dynamic_validation)
        if timeout_static_analysis == None:
            self.timeout_static_analysis = TIMEOUT_STATIC_ANALYSIS
        else:
            self.timeout_static_analysis=int(timeout_static_analysis)
        if timeout_symbolic_execution != None:
            self.timeout_symbolic_execution = int(timeout_symbolic_execution)
            self.timeout_dynamic_validation = self.timeout_symbolic_execution + self.timeout_static_analysis
        else:
            if timeout_dynamic_validation != None and timeout_static_analysis != None:
                self.timeout_symbolic_execution = None
            else:
                self.timeout_symbolic_execution = 365*24*60*60
        self.guided_execution = guided
        self.be_bully = be_bully
        self.se_poc = se_poc

    def do_symbolic_execution(self, case, context, i386, max_round=3, raw_tracing=False, timeout=None):
        path_regx = r'path2(MemWrite|FuncPtrDef)-(\d+)-\d+'
        self.logger.info("initial environ of symbolic execution")
        #if not self.guided_execution:
        #    return 1
        if timeout != None:
            self.timeout_symbolic_execution = timeout
        else:
            self.timeout_symbolic_execution = self.timeout_dynamic_validation - self.timeout_static_analysis
        workdir = 'sym-' + context['workdir']
        static_workdir = 'static-' + context['workdir']
        self.sa = static_analysis.StaticAnalysis(logger=self.case_logger, proj_path=self.project_path, workdir=static_workdir, index=self.index, case_path=self.current_case_path, linux_folder=self.linux_folder, max_compiling_kernel=self.max_compiling_kernel)

        linux_path = os.path.join(self.current_case_path, self.linux_folder)
        """target = os.path.join(self.package_path, "scripts/deploy_linux.sh")
        utilities.chmodX(target)
        p = Popen([target, self.compiler, "0", linux_path, self.package_path, case["commit"], case["config"],  "1"],
                stdout=PIPE,
                stderr=STDOUT)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        if exitcode != 0:
            self.logger.error("Error occur when compiling kernel")
            return
        """
        arch = 'amd64'
        if i386:
            arch = 'i386'

        sym_folder = os.path.join(self.current_case_path, workdir)
        if os.path.isdir(sym_folder):
            n=1
            dest_path = "{}-{}".format(sym_folder, n)
            while(1):
                if not os.path.isdir(dest_path):
                    shutil.move(sym_folder, dest_path)
                    break
                else:
                    n += 1
                    dest_path = "{}-{}".format(sym_folder, n)

        static_analysis_result_paths = self.current_case_path + "/{}/paths".format(static_workdir)
        if not os.path.isdir(static_analysis_result_paths):
            path_files = [None]
        else:
            path_files = os.listdir(static_analysis_result_paths)
            if path_files == []:
                path_files = [None]

        paths = []
        terminating_func = ''
        if self.guided_execution:
            for each_file in path_files:
                if each_file != None:
                    n_basic_block = utilities.regx_get(path_regx, each_file, 1)
                    if n_basic_block == None and each_file == 'TerminatingFunc':
                        terminating_func_path = os.path.join(static_analysis_result_paths, each_file)
                        with open(terminating_func_path, 'r') as f:
                            func = f.readline()
                            terminating_func = func.strip('\n')
                            continue
                    if int(n_basic_block) < 40:
                        continue
                    guided_path = os.path.join(static_analysis_result_paths, each_file)
                    p = self.retrieve_guided_paths(guided_path)
                    if p != []:
                        paths.append(p)

        os.mkdir(sym_folder)
        is_propagating_global = False
        result = StateManager.NO_ADDITIONAL_USE
        exception_count = 0
        flag_stop_execution = False
        if terminating_func == '' and self.guided_execution:
            self.logger.info("No terminating function found, switch to unguided symbolic execution")
            paths = []
        for i in range(0, max_round):
            cur_sym_log = sym_folder + "/symbolic_execution.log" + "-" + str(i)
            sym_logger = self.__init_logger(cur_sym_log)
            sym_logger.info("round {}: symbolic tracing".format(i))
            sym = sym_exec.SymExec(logger=sym_logger, workdir=sym_folder, index=self.index, debug=self.debug)
            sym.setup_vm(linux_path, arch, self.ssh_port, self.image_path, self.gdb_port, self.qemu_monitor_port, proj_path=sym_folder, cpu="2", mem="2G", logger=self.case_logger, hash_tag=self.hash_val[:7], log_name="vm.log", log_suffix="-{}".format(i),  timeout=self.timeout_symbolic_execution+5*60)
            p = None
            try:
                p = sym.run_vm()
            except QemuIsDead:
                self.logger.error("Error occur when executing symbolic tracing: QemuIsDead")
                if self.be_bully:
                    self.kill_proc_by_port(self.ssh_port)
            except AngrRefuseToLoadKernel:
                self.logger.error("Error occur when loading kernel into angr: AngrRefuseToLoadKernel")
                sym.cleanup()
                del sym
                continue
            except KasanReportEntryNotFound:
                sym_logger.warning("Kasan report entry not found")
                sym.cleanup()
                del sym
                continue
            except Exception as e:
                self.logger.error("Unknown error occur: {}".format(e))
                sym.cleanup()
                del sym
                continue
            if p == None:
                self.logger.error("Fail to launch qemu")
                sym.cleanup()
                del sym
                continue
            exitcode = p.poll()
            if exitcode != None:
                err = 'Unknown reason'
                if exitcode == -9:
                    err = 'SIGKILL'
                self.logger.error('QEMU exit due to: {}'.format(err))
                sym.cleanup()
                del sym
                continue
            sym_logger.info("Uploading poc and triggering the crash")
            if self.se_poc == None:
                ok = self.crash_checker.upload_exp(context['repro'], self.ssh_port, case["syzkaller"], context['type'], context["c_repro"], i386, 0, sym.vm.qemu_logger)
                if ok == 0:
                    self.logger.error("Error occur at upload exp")
                    sym.cleanup()
                    del sym
                    continue
                
                if context['command'] != '':
                    self.crash_checker.run_exp(context['command'], self.ssh_port, utilities.CASE, ok, i386, 0, sym.vm.qemu_logger)
                else:
                    self.crash_checker.run_exp(case['syz_repro'], self.ssh_port, utilities.URL, ok, i386, 0, sym.vm.qemu_logger)
            else:
                ok = self.crash_checker.upload_custom_exp(self.se_poc, self.ssh_port, sym_logger)
                if ok != 0:
                    self.logger.error("Error occur at upload exp")
                    sym.cleanup()
                    del sym
                    continue

                self.crash_checker.run_custom_exp(self.ssh_port, sym_logger)
            try:
                if paths != []:
                    self.logger.info("Running under-constrained symbolic execution with guided paths")
                else:
                    self.logger.info("Running under-constrained symbolic execution")
                """p = []
                p.append({'cond': 0xffffffff83234a29, 'correct': 0xffffffff83234a2b, 'wrong': 0xffffffff832349a9})
                p.append({'cond': 0xffffffff83234a2b, 'correct': 0xffffffff83234a5a, 'wrong': 0xffffffff832349a9})
                p.append({'cond': 0xffffffff83e62f10, 'correct': 0xffffffff83e62e39, 'wrong': 0xffffffff83e7d5f0})
                p.append({'cond': 0xffffffff83e5fe76, 'correct': 0xffffffff83e5fe8b, 'wrong': 0xffffffff83e7ba0e})
                p.append({'cond': 0xffffffff83e5fea3, 'correct': 0xffffffff83e5feb5, 'wrong': 0xffffffff83e5fec0})
                paths = [p]"""
                ret = sym.run_sym(path=paths, terminating_func=terminating_func, raw_tracing=raw_tracing, timeout=self.timeout_symbolic_execution)
                if ret == None:
                    self.logger.warning("Can not locate the vulnerable memory")
                    sym.cleanup()
                    del sym
                    continue
                result |= ret
                if ret == 0:
                    self.logger.warning("No additional use")
                sym.cleanup()
                del sym
                break
                #if ret != None and len(ret) > 0:
                #    is_propagating_global = True
            except VulnerabilityNotTrigger:
                self.logger.warning("Can not trigger vulnerability. Abaondoned")
                exception_count += 1
            except AbnormalGDBBehavior:
                sym_logger.warning("Abnormal GDB behavior occured")
                exception_count += 1
            except QemuIsDead:
                self.logger.error("Error occur when executing symbolic tracing: QemuIsDead")
                exception_count += 1
            except InvalidCPU:
                self.logger.error("Fail to determine which cpu is using for current context")
                exception_count += 1
            #except Exception as e:
            #    sym_logger.error("Unknown exception occur during symboulic execution: {}".format(e))
            sym.cleanup()
            del sym
            time.sleep(1)
        if max_round == exception_count:
            return 1
        if result & StateManager.CONTROL_FLOW_HIJACK:
            self.logger.warning("Control flow hijack found")
        if result & StateManager.ARBITRARY_VALUE_WRITE:
            self.logger.warning("Arbitrary value write found")
        if result & StateManager.FINITE_VALUE_WRITE:
            self.logger.warning("Finite value write found")
        if result & StateManager.ARBITRARY_ADDR_WRITE:
            self.logger.warning("Arbitrary address write found")
        if result & StateManager.FINITE_ADDR_WRITE:
            self.logger.warning("Finite address write found")
        if result & StateManager.OOB_UAF_WRITE:
            self.logger.warning("OOB/UAF write found")
        if result & StateManager.INVALID_FREE:
            self.logger.warning("Invalid free found")
        """if is_propagating_global:
            if raw_tracing:
                self.logger.warning("{} access to global/local variables on symbolic tracing".format(self.hash_val))
            #self.__create_stamp(stamp_symbolic_execution)
        elif exception_count < max_round:
            if raw_tracing:
                self.logger.warning("{} has no access to variables".format(self.hash_val))
            #self.__create_stamp(stamp_symbolic_execution)
        else:
            self.logger.warning("Can not trigger vulnerability. Abaondoned")"""
        
        return result == StateManager.NO_ADDITIONAL_USE
    
    def retrieve_guided_paths(self, guided_path):
        paths = []
        if guided_path != None:
            with open(guided_path, 'r') as f:
                text = f.readlines()
                for site in text:
                    fesible_condition = False
                    site = site.strip('\n')
                    tmp = site.split(' ')
                    if site == '$':
                        break
                    if len(tmp) == 1:
                        t = tmp[0].split(':')
                        file = t[0]
                        line = t[1]
                        paths.append({'file': file, 'line': line})
                        break
                    base_index = 0
                    if tmp[0] == '*':
                        fesible_condition = True
                        base_index = 1
                    cond = tmp[base_index].split(':')
                    correct = tmp[base_index+1].split(':')
                    wrong = tmp[base_index+2].split(':')
                    paths.append({'cond': {'file': cond[0], 'line': cond[1], 'feasible': True}, 'correct': {'file': correct[0], 'line': correct[1], 'feasible': True}, 'wrong': {'file': wrong[0], 'line': wrong[1], 'feasible': False}})
                    if fesible_condition:
                        paths.append({'cond': {'file': cond[0], 'line': cond[1], 'feasible': True}, 'wrong': {'file': correct[0], 'line': correct[1], 'feasible': True}, 'correct': {'file': wrong[0], 'line': wrong[1], 'feasible': False}})
        return paths


    def do_static_analysis(self, case, context):
        if context['type'] == utilities.URL:
            raw = utilities.request_get(context['report'])
            report = raw.text
        else:
            f = open(context['report'], 'r')
            raw = f.readlines()
            report = "".join(raw)
        offset = context['offset']
        size = context['size']
        workdir = 'static-' + context['workdir']
        if offset == None:
            self.logger.info("No valid offset of vulnerable object for static analysis")
            return
        self.sa = static_analysis.StaticAnalysis(logger=self.case_logger, proj_path=self.project_path, index=self.index, workdir=workdir, case_path=self.current_case_path, linux_folder=self.linux_folder, max_compiling_kernel=self.max_compiling_kernel, timeout=self.timeout_static_analysis)
        vul_site, func_site, func = self.sa.KasanVulnChecker(report)
        if vul_site == None or func_site == None or func == None:
            self.logger.error("No valid Calltrace for static analysis")
            return
        
        static_folder = os.path.join(self.current_case_path, workdir)
        if os.path.isdir(static_folder):
            n=1
            dest_path = "{}-{}".format(static_folder, n)
            while(1):
                if not os.path.isdir(dest_path):
                    shutil.move(static_folder, dest_path)
                    break
                else:
                    n += 1
                    dest_path = "{}-{}".format(static_folder, n)
        os.mkdir(static_folder)
        
        self.logger.info("prepare for static analysis")
        r = self.sa.prepare_static_analysis(case, vul_site, func_site)
        if r != 0:
            raise CompilingError
        # Before save the Calltrace, we need to checkout to a right commit
        report_list = report.split('\n')
        kasan_report = utilities.only_kasan_calltrace(report_list)
        trace = utilities.extrace_call_trace(kasan_report)
        if self.sa.saveCallTrace2File(trace, vul_site):
            self.logger.error("Error occur at saveCallTrace2File, please manually add boundaries in {}".format(self.sa.work_path, "CallTrace"))
        r, time_on_static_analysis = self.sa.run_static_analysis(offset, size)
        if r != 0 and r != 1:
            self.logger.error("Error occur during taint analysis")
        if self.timeout_symbolic_execution == None:
            self.timeout_symbolic_execution = self.timeout_dynamic_validation - time_on_static_analysis
    
    def do_reproducing_ori_poc(self, case, hash_val, i386):
        self.logger.info("Try to triger the OOB/UAF by running original poc")
        self.case_info_logger.info("compiler: "+self.compiler)
        hunted_type_without_mutating = False
        title = None
        report, trigger = self.crash_checker.read_crash(case["syz_repro"], case["syzkaller"], None, 0, case["c_repro"], i386)
        if trigger:
            hunted_type_without_mutating, title = self.KasanChecker(report, hash_val)
        self.create_reproduced_ori_poc_stamp()
        return hunted_type_without_mutating, title
    
    def KasanChecker(self, report, hash_val):
        title = None
        ret = False
        flag_double_free = False
        flag_kasan_write = False
        flag_kasan_read = False
        if report != []:
            for each in report:
                for line in each:
                    if utilities.regx_match(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line) or \
                        utilities.regx_match(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line):
                        m = re.search(r'BUG: (KASAN: [a-z\\-]+ in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                        m = re.search(r'BUG: (KASAN: double-free or invalid-free in [a-zA-Z0-9_]+)', line)
                        if m != None and len(m.groups()) > 0:
                            title = m.groups()[0]
                    if utilities.regx_match(utilities.double_free_regx, line) and not flag_double_free:
                            ret = True
                            self.crash_checker.logger.info("Double free without mutating")
                            self.logger.info("Write to ConfirmedDoubleFree")
                            self.__write_to_DoubleFree(hash_val)
                            self.__write_to_ConfirmedDoubleFree(hash_val)
                            flag_double_free = True
                            break
                    if utilities.regx_match(utilities.kasan_write_addr_regx, line) and not flag_kasan_write:
                            ret = True
                            self.crash_checker.logger.info("OOB/UAF Write without mutating")
                            self.logger.info("Write to ConfirmedAbnormallyMemWrite")
                            self.__write_to_AbnormallyMemWrite(hash_val)
                            flag_kasan_write = True
                            break
                    if self.store_read and utilities.regx_match(utilities.kasan_read_addr_regx, line) and not flag_kasan_read:
                            ret = True
                            self.crash_checker.logger.info("OOB/UAF Read without mutating")
                            self.logger.info("Write to ConfirmedAbnormallyMemRead")
                            self.__write_to_AbnormallyMemRead(hash_val)
                            flag_kasan_read = True
                            break
        return ret, title
    
    def get_buggy_contexts(self, case):
      ret = []
      ori_ready = False
      if self.store_read:
        # OOB/UAF read
        offset = case["vul_offset"]
        size = case["obj_size"]
        if offset != None and size != None:
          ori_ready = True
          ret.append({'title':case["title"], 'workdir': 'ori', 'offset': offset, 'size': size, 'repro': case["syz_repro"], 'report': case['report'], 'type': utilities.URL, 'c_repro': case["syz_repro"], 'command': ''})
      output = os.path.join(self.current_case_path, "output")
      if os.path.exists(output):
          all_cases = os.listdir(output)
          for each_case in all_cases:
              if each_case == 'ori' and ori_ready:
                  continue
              case_base = os.path.join(output, each_case)
              description = os.path.join(case_base, "description")
              if not os.path.exists(description):
                  continue
              f = open(description, 'r')
              title = f.readline()
              f.close()
              if utilities.regx_match('KASAN', title):
                  report = os.path.join(case_base, "repro.report")
                  if not os.path.exists(report):
                      continue
                  f = open(report, 'r')
                  texts = f.readlines()
                  offset, size, _ = utilities.extract_vul_obj_offset_and_size(texts)
                  prog = os.path.join(case_base, "repro.prog")
                  command = os.path.join(case_base, "repro.command")
                  if not os.path.isfile(command):
                      command = ''
                  ret.append({'title':title, 'workdir': each_case[:7], 'offset': offset, 'size': size, 'repro': prog,  'report': report, 'type': utilities.CASE, 'c_repro': None, 'command': command})
      return ret
    
    def copy_only_impact(self, input_log, output_log):
        flag_record = False
        new_text = []
        with open(input_log, 'r') as f:
            text = f.readlines()
            for line in text:
                if utilities.regx_match(utilities.kasan_oob_regx, line) or \
                    utilities.regx_match(utilities.kasan_uaf_regx, line) or \
                    utilities.regx_match(utilities.double_free_regx, line):
                    flag_record = True
                if flag_record:
                    new_text.append(line)
        with open(output_log, 'w') as f:
            f.writelines(new_text)
            f.truncate()
    
    def generate_decent_report(self, input_log, output_log):
        syzkaller_workdir = os.path.join(self.current_case_path, "gopath/src/github.com/google/syzkaller/workdir")
        files = os.listdir(syzkaller_workdir)
        cfg_path = ""
        for each_file in files:
            if each_file.endswith('.cfg'):
                cfg_path = os.path.join(syzkaller_workdir, each_file)
                break
        syz_logparser = os.path.join(self.current_case_path, "gopath/src/github.com/google/syzkaller/bin/syz-logparser")
        if not os.path.isfile(syz_logparser):
            self.case_logger.info("Cannot find syz-logparser on current case")
            return
        cmd = [syz_logparser, "-i", input_log, "-o", output_log, "-cfg", cfg_path]
        p = Popen(cmd, stdin=PIPE, stdout=PIPE)
        with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
        if exitcode != 0:
            self.case_logger.info("Fail to generate a decent report from bug log")
        return
    
    def kill_proc_by_port(self, ssh_port):
        p = Popen("lsof -i :{} | awk '{{print $2}}'".format(ssh_port), shell=True, stdout=PIPE, stderr=PIPE)
        is_pid = False
        pid = -1
        with p.stdout as pipe:
            for line in iter(pipe.readline, b''):
                line = line.strip().decode('utf-8')
                if line == 'PID':
                    is_pid = True
                    continue
                if is_pid:
                    pid = int(line)
                    call("kill -9 {}".format(pid), shell=True)
                    break
    
    def remove_gopath(self, src):
        gopath = os.path.join(src, "gopath")
        try:
            shutil.rmtree(gopath)
        except Exception as e:
            self.logger.error("Fail to remove {}".format(gopath))
    
    def init_crash_checker(self, port):
        self.crash_checker = CrashChecker(
            self.project_path,
            self.current_case_path,
            port,
            self.logger,
            self.debug,
            self.index,
            self.max_qemu_for_one_case,
            store_read=self.store_read,
            compiler=self.compiler,
            max_compiling_kernel=self.max_compiling_kernel)
    
    def write_to_confirm(self, hash_val, new_impact_type):
        if new_impact_type & utilities.AbMemRead:
            self.__write_to_ConfirmedAbnormallyMemRead(hash_val)
        if new_impact_type & utilities.AbMemWrite:
            self.__write_to_ConfirmedAbnormallyMemWrite(hash_val)
        if new_impact_type & utilities.InvFree:
            self.__write_to_ConfirmedDoubleFree(hash_val)

    def reproduced_ori_poc(self, hash_val, folder):
        return self.__check_stamp(stamp_reproduce_ori_poc, hash_val[:7], folder)
    
    def finished_fuzzing(self, hash_val, folder):
        return self.__check_stamp(stamp_finish_fuzzing, hash_val[:7], folder)
    
    def finished_symbolic_execution(self, hash_val, folder):
        return self.__check_stamp(stamp_symbolic_execution, hash_val[:7], folder)
    
    def finished_static_analysis(self, hash_val, folder):
        return self.__check_stamp(stamp_static_analysis, hash_val[:7], folder)

    def create_finished_fuzzing_stamp(self):
        return self.__create_stamp(stamp_finish_fuzzing)
    
    def create_finished_symbolic_execution_stamp(self):
        return self.__create_stamp(stamp_symbolic_execution)

    def create_finished_static_analysis_stamp(self):
        return self.__create_stamp(stamp_static_analysis)
    
    def create_reproduced_ori_poc_stamp(self):
        return self.__create_stamp(stamp_reproduce_ori_poc)
    
    def cleanup_finished_fuzzing(self, hash_val):
        self.__clean_stamp(stamp_finish_fuzzing, hash_val[:7])
    
    def cleanup_built_kernel(self, hash_val):
        self.__clean_stamp(stamp_build_kernel, hash_val[:7])
    
    def cleanup_built_syzkaller(self, hash_val):
        self.__clean_stamp(stamp_build_syzkaller, hash_val[:7])
    
    def cleanup_reproduced_ori_poc(self, hash_val):
        self.__clean_stamp(stamp_reproduce_ori_poc, hash_val[:7])
    
    def cleanup_finished_symbolic_execution(self, hash_val):
        self.__clean_stamp(stamp_symbolic_execution, hash_val[:7])

    def cleanup_finished_static_analysis(self, hash_val):
        self.__clean_stamp(stamp_static_analysis, hash_val[:7])
    
    def __create_stamp(self, name):
        self.logger.info("Create stamp {}".format(name))
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        call(['touch',stamp_path])
    
    def __check_stamp(self, name, hash_val, folder):
        stamp_path1 = "{}/work/{}/{}/.stamp/{}".format(self.project_path, folder, hash_val, name)
        return os.path.isfile(stamp_path1)
    
    def __clean_stamp(self, name, hash_val):
        stamp_path = "{}/.stamp/{}".format(self.current_case_path, name)
        if os.path.isfile(stamp_path):
            os.remove(stamp_path)
    
    def __write_to_AbnormallyMemWrite(self, hash_val):
        self.__write_to(hash_val, "AbnormallyMemWrite")
    
    def __write_to_ConfirmedAbnormallyMemWrite(self, hash_val):
        self.__write_to(hash_val, "ConfirmedAbnormallyMemWrite")
    
    def __write_to_AbnormallyMemRead(self, hash_val):
        self.__write_to(hash_val, "AbnormallyMemRead")
    
    def __write_to_ConfirmedAbnormallyMemRead(self, hash_val):
        self.__write_to(hash_val, "ConfirmedAbnormallyMemRead")
    
    def __write_to_DoubleFree(self, hash_val):
        self.__write_to(hash_val, "DoubleFree")
    
    def __write_to_ConfirmedDoubleFree(self, hash_val):
        self.__write_to(hash_val, "ConfirmedDoubleFree")
    
    def __write_to(self, hash_val, name):
        with open("{}/work/{}".format(self.project_path, name), "a+") as f:
            f.write(hash_val[:7]+"\n")

    def __log_subprocess_output(self, pipe, log_level):
        for line in iter(pipe.readline, b''):
            if log_level == logging.INFO:
                self.case_logger.info(line)
            if log_level == logging.DEBUG:
                self.case_logger.debug(line)
    
    def __init_logger(self, log_path):
        handler = logging.FileHandler(log_path)
        format = logging.Formatter('%(asctime)s Thread {}: %(message)s'.format(self.index))
        handler.setFormatter(format)
        logger = logging.getLogger(log_path)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if self.debug:
            logger.propagate = True
            logger.setLevel(logging.DEBUG)
        return logger
