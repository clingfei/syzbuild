import os
import glob

class Extracter():
  def __init__(self, folder, signle=False, batch= False):
    """_summary_

    Args:
        folder (_type_): _description_
        signle: only one console log file
        batch: batch console log with name log0,log1....
    """

    # If we do not chose signle or batch
    # will check the folder to chose signle mode or batch mode
    self.folder = folder

    self.signle = batch
    self.file = None

    self.batch = signle
    self.files = []

    # all the progs
    self.progs = []

    if not os.path.exists(self.folder):
      print("folder must exists")
      exit(-1)

    if not self.signle:
      log = os.path.join(self.folder, "console")
      try:
        with open(log, "r") as fp:
          self.signle = True
          self.file = log
          print("single mode: log")
      except IOError:
        print("try console failed. try next...")

    if not self.signle:
      log = os.path.join(folder, "console_log")
      try:
        with open(log, "r") as fp:
          self.signle = True
          self.file = log
          print("single mode: log")
      except IOError:
        print("try console_log failed. try next...")

    if not self.signle:
      log = os.path.join(folder, "log")
      try:
        with open(log, "r") as fp:
          self.signle = True
          self.file = log
          print("single mode: log")
      except IOError:
        print("try log failed. try next...")

    if self.signle:
      self.extract()
    else:
      self.batch = True
      self.files = glob.glob(self.folder+"/log*")
      self.extract()


  def extract(self):
    # TODO: timestamp && prog
    if not self.signle and not self.batch:
      print("failed no signle and no mutiple")
      return
    elif self.signle and self.batch:
      print("failed signal and mutiple")
      return
    elif self.signle and not self.batch:
      with open(self.file, 'r') as fp:
        tmp = []
        lines = fp.read().split('\n')
        eof = len(lines)
        for i,line in enumerate(lines):
          if "executing program " in line:
            begin, end = i,i
            for j in range(i, eof):
              if lines[j] == "":
                end = j
                break
            if begin == end:
              pass
            else:
              tmp.append((begin,end))
          elif line.startswith("["):
            continue
          else:
            continue
        for i,prog in enumerate(tmp):
          cnt = ""
          b = prog[0]
          e = prog[1]
          for l in range(b+1,e):
            cnt += lines[l]+'\n'
          self.progs.append(cnt)

    elif self.batch and not self.signle:
      for file in self.files:
        with open(file, 'r') as fp:
          tmp = []
          lines = fp.read().split('\n')
          eof = len(lines)
          for i,line in enumerate(lines):
            if "executing program " in line:
              begin, end = i,i
              for j in range(i, eof):
                if lines[j] == "":
                  end = j
                  break
              if begin == end:
                pass
              else:
                tmp.append((begin,end))
            elif line.startswith("["):
              continue
            else:
              continue
          for i,prog in enumerate(tmp):
            cnt = ""
            b = prog[0]
            e = prog[1]
            for l in range(b+1,e):
              cnt += lines[l]+'\n'
            self.progs.append(cnt)
    else:
      print("wtf man")

  def split_save(self, folder=""):
    if not folder:
      folder = self.folder
    dst = os.path.join(folder, "progs")
    if os.path.exists(dst):
      # FIXME: don't be so aggressive
      # shutil.rmtree(dst)
      print("progs existed, please check and try again")
    os.mkdir(dst)

    for i,prog in enumerate(self.progs):
      open(os.path.join(dst, "{0}.prog".format(i)), "wb").write(prog.encode())

  def merge_save(self):
    with open(os.path.join(self.folder, "merge.prog"), "ab") as fp:
      for _,prog in enumerate(self.progs):
        cnt = ""
        b = prog[0]
        e = prog[1]
        for l in range(b+1,e):
          cnt += lines[l]+ '\n'
        fp.write(cnt.encode())


if __name__ == "__main__":
  ex = Extracter("/home/spark/foobar/3ba8f209")
  ex.extract()
  ex.split_save("/tmp/")

