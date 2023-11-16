import logging
import sys

class Datastorer():
  def __init__(self, assets=False, debug=False):

    self.url = ""
    self.title = ""
    self.patch = ""

    # only 8 bytes, unique identifier for datastorer
    self.hash = ""

    self.cases = {}
    self.assets = assets
    self.debug = debug

    self.__init_logger()

  def __init_logger(self):
    handler = logging.StreamHandler(sys.stderr)
    format = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(format)
    self.logger = logging.getLogger(__name__)
    if self.debug:
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = True
    else:
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
    self.logger.addHandler(handler)

  def prepare(self, idx):
    self.logger.info("prepare case")
    self.cases[idx] = {}
    # kernel
    self.cases[idx]["kernel"] = None
    self.cases[idx]["commit"] = None
    self.cases[idx]["is_upstream"] = False
    self.cases[idx]["config"] = None
    # syzkaller
    self.cases[idx]["syzkaller"] = None
    # compiler
    self.cases[idx]["gcc"] = None
    self.cases[idx]['clang'] = None
    self.cases[idx]['version'] = None
    # console log
    self.cases[idx]["log"] = None
    # crash
    self.cases[idx]["report"] = None
    # reproduce
    self.cases[idx]["syz"] = None
    self.cases[idx]["cpp"] = None
    # assets infomation
    if self.assets:
        self.cases[idx]["assets"] = []
    # manager name
    self.cases[idx]["manager"] = None
