import os
import sys
import shutil
import argparse
from IPython import embed

def split(progs):
  dst = os.path.join(folder, "./progs")
  if os.path.exists(dst):
    shutil.rmtree(dst)
  os.mkdir(dst)

  for i,prog in enumerate(progs):
    cnt = ""
    b = prog[0]
    e = prog[1]
    for l in range(b+1,e):
      cnt += lines[l]+ '\n'
    open(os.path.join(dst, "{0}.prog".format(i)),"wb").write(cnt.encode())
    # sys.stdout.write(str(i)+"\n")
    # print(file)

def add(progs):
  return


def merge(progs):
  # dst = os.path.join(folder, "./progs")
  # if os.path.exists(dst):
  #   shutil.rmtree(dst)
  # os.mkdir(dst)

  with open(os.path.join(folder, "merge.prog"), "ab") as fp:
    for i,prog in enumerate(progs):
      cnt = ""
      b = prog[0]
      e = prog[1]
      for l in range(b+1,e):
        cnt += lines[l]+ '\n'
      fp.write(cnt.encode())

if __name__ == "__main__":
  # parse = argparse.ArgumentParser()
  # parse.parse_args()
  folder = ""
  if len(sys.argv) == 2:
    folder = sys.argv[1]
  else:
    print("arg2 must set the folder path")
    exit(-1)

  ok = False
  if not ok:
    log = os.path.join(folder, "console")
    try:
      with open(log, "r") as fp:
        lines = fp.read().split('\n')
      ok = True
    except IOError:
      print("try consolelog failed")
  if not ok:
    log = os.path.join(folder, "console_log")
    try:
      with open(log, "r") as fp:
        lines = fp.read().split('\n')
      ok = True
    except IOError:
      print("try crashlog failed. please check...")
      exit(-1)

  if not ok:
      print('not ok')
      exit(-1)

  progs = []

  # TODO: timestamp && prog
  eof = len(lines)
  for i,line in enumerate(lines):
    if "executing program " in line:
      # print("begin: ", i)
      begin, end = i,i
      for j in range(i, eof):
        if lines[j] == "":
          end = j
          break
      if begin == end:
        pass
      else:
        progs.append((begin,end))
    elif line.startswith("["):
      continue
    else:
      continue

  # merge(progs)
  # split(progs)


