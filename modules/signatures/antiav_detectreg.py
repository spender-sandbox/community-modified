# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import re

class AntiAVDetectReg(Signature):
    name = "antiav_detectreg"
    description = "Attempts to identify installed AV products by registry key"
    severity = 3
    categories = ["anti-av"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        reg_indicators = [
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\Avg\\\\SystemValues$"
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Avg$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?AVAST\\ Software\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Avira$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Bitdefender$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?BitDefender\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Coranti$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Data\\ Fellows\\\\F-Secure$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Doctor\\ Web$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?ESET$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?ESET\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?G\\ Data$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Symantec$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?KasperskyLab\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?McAfee\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?McAfee\.com\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Microsoft\\ Antimalware$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Network\\ Associates\\\\TVD$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Panda\\ Software$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?rising$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Softed\\\\ViGUARD$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Sophos$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Sophos\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?TrendMicro$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?VBA32$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Zone\\ Labs\\\\ZoneAlarm$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\App\\ Paths\\\\mbam.exe$",
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\Avg\\\\SystemValues$"
        ]
        found = False
        for indicator in reg_indicators:
            reg_match = self.check_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                for match in reg_match:
                    self.data.append({"key" : match })
                found = True
        return found
