# Copyright (C) 2015 Will Metcalf william.metcalf@gmail.com 
#
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import struct

try:
    import re2 as re
except ImportError:
    import re

class OfficeDLWritesEXE(Signature):
    name = "office_dl_write_exe"
    description = "Likely Malicious Office Document DL/Write EXE to disk"
    severity = 3 
    categories = ["virus"]
    authors = ["Will Metcalf"]
    minimum = "1.2"
    evented = True
    match = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.data = []
        self.exere = re.compile(r"\.exe$")
        self.office_proc_list =["wordview.exe","winword.exe","excel.exe","powerpnt.exe","outlook.exe"]        

    filter_apinames = set(["NtWriteFile","URLDownloadToFileW","HttpOpenRequestW","InternetReadFile","InternetCrackUrlW"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.office_proc_list:
            if call["api"] == "NtWriteFile":
                buff = self.get_raw_argument(call, "Buffer")
                if buff and len(buff) > 2 and buff[0]+buff[1] == "MZ" and "This program" in buff:
                    self.data.append({"office_dl_write_exe": "%s_NtWriteFile_%s" % (pname,self.get_argument(call, "HandleName"))})
            if call["api"] == "InternetReadFile":
                buff = self.get_raw_argument(call, "Buffer")
                if buff and len(buff) > 2 and buff[0]+buff[1] == "MZ" and "This program" in buff:
                    self.data.append({"office_dl_write_exe": "%s_InternetReadFile" % (pname)})
            if call["api"] == "URLDownloadToFileW":
                buff = self.get_argument(call, "FileName").lower()
                if self.exere.search(buff) != None:
                     self.data.append({"office_dl_write_exe": "%s_URLDownloadToFileW_%s" % (pname,buff)})
            if call["api"] == "HttpOpenRequestW":
                buff = self.get_argument(call, "Path").lower()
                if self.exere.search(buff) != None:
                     self.data.append({"office_dl_write_exe": "%s_HttpOpenRequestW_%s" % (pname,buff)})
            if call["api"] == "InternetCrackUrlW":
                buff = self.get_argument(call, "Url").lower()
                if self.exere.search(buff) != None:
                     self.data.append({"office_dl_write_exe": "%s_InternetCrackUrlW_%s" % (pname,buff)})
        return None

    def on_complete(self):
        if self.data:
            return True
        else:
            return False
