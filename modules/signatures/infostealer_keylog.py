# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from lib.cuckoo.common.abstracts import Signature

class KeyLogger(Signature):
    name = "infostealer_keylog"
    description = "Sniffs keystrokes"
    severity = 3
    categories = ["infostealer"]
    authors = ["Accuvant"]
    minimum = "1.0"
    evented = True

    filter_apinames = set(["SetWindowsHookExA","SetWindowsHookExW"])

    def on_call(self, call, process):
        id = int(self.get_argument(call, "HookIdentifier"), 10)
        thread = int(self.get_argument(call, "ThreadId"), 10)

        # global WH_KEYBOARD or WH_KEYBOARD_LL hook
        if thread == 0 and (id == 2 or id == 13):
            return True
