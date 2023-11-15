import os
import subprocess
import logging

class Fuzzer():

  def __init__():
    pass

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

  def run():
    pass

  def run_syzkaller(self, hash_val, limitedMutation):
    self.logger.info("run syzkaller".format(self.index))
    syzkaller = os.path.join(self.syzkaller_path, "bin/syz-manager")
    exitcode = 4
    # First round, we only enable limited syscalls.
    # If failed to trigger a write crash, we enable more syscalls to run it again
    for _ in range(0, 3):
      if self.logger.level == logging.DEBUG:
        p = subprocess.Popen([syzkaller,
                   "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash_val[:7]),
                   "-debug",
                   "-poc"
                  ],
              stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT
              )
        with p.stdout:
          self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()

        if not limitedMutation:
          p = subprocess.Popen([syzkaller,
                     "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash_val[:7]),
                     "-debug"
                    ],
              stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT
              )
          with p.stdout:
            self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()
      else:
        p = subprocess.Popen([syzkaller,
                   "--config={}/workdir/{}-poc.cfg".format(self.syzkaller_path, hash_val[:7]),
                   "-poc"
                  ],
            stdout = subprocess.PIPE,
            stderr = subprocess.STDOUT
            )
        with p.stdout:
          self.__log_subprocess_output(p.stdout, logging.INFO)
        exitcode = p.wait()

        if not limitedMutation:
          p = subprocess.Popen([syzkaller,
                     "--config={}/workdir/{}.cfg".format(self.syzkaller_path, hash_val[:7])],
              stdout = subprocess.PIPE,
              stderr = subprocess.STDOUT
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