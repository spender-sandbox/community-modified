# Copyright (C) 2016 KillerInstinct, Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class APISpamming(Signature):
    name = "api_spamming"
    description = "Attempts to repeatedly call a single API many times in order to delay analysis time"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["KillerInstinct", "Brad Spengler"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.spam = dict()
        self.spam_limit = 10000
 
    def on_call(self, call, process):
        if call["repeated"] < self.spam_limit:
            return None
        if process not in self.spam:
            self.spam[process] = {}
        if call["api"] not in self.spam[process]:
            self.spam[process][call["api"]] = call["repeated"]
        else:
            self.spam[process][call["api"]] += call["repeated"]

    def on_complete(self):
        spam_apis_whitelist = {
             "c:\\program files\\internet explorer\\iexplore.exe": ["NtQuerySystemTime", "GetSystemTimeAsFileTime", "GetSystemTime"],
             "c:\\program files\\microsoft office\\office14\\winword.exe": ["GetLocalTime"],
             "c:\\windows\\system32\\wbem\\wmiprvse.exe": ["GetSystemTimeAsFileTime"],
             "c:\\windows\\system32\\wscript.exe": ["GetLocalTime", "NtQuerySystemTime"],
        }
        ret = False
        for proc, apis in self.spam.iteritems():
            modulepathlower = proc["module_path"].lower()
            do_check = False
            if modulepathlower in spam_apis_whitelist:
                do_check = True
            for apiname, count in apis.iteritems():
                if not do_check or apiname not in spam_apis_whitelist[modulepathlower]:
                    self.data.append({"Spam": "{0} ({1}) called API {2} {3} times".format(
                            proc["process_name"], proc["process_id"], apiname, count)})
                    ret = True

        return ret
