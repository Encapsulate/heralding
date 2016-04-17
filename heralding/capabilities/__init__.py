import glob
import os

# Detect all modules
for fullname in glob.glob(os.path.dirname(__file__) + "/*.py"):
    name = os.path.basename(fullname)
    # __init__ and handlerbase are not capabilities, so ignore them
    # also ignore ssh and telnet until telnetsrvlib har python3 support
    if name[:-3] == "__init__" or name[:-3] == "handlerbase" or name[:-3] == "ssh" or name[:-3] == "telnet":
        pass
    else:
        __import__("heralding.capabilities." + name[:-3])
