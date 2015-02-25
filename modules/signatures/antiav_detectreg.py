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
            ".*\\\\Software\\\\Avg$",
            ".*\\\\Software\\\\AVAST\\ Software\\\\.*",
            ".*\\\\Software\\\\Avira$",
            ".*\\\\Software\\\\Bitdefender$",
            ".*\\\\Software\\\\BitDefender\\\\.*",
            ".*\\\\Software\\\\Coranti$",
            ".*\\\\Software\\\\Data\\ Fellows\\\\F-Secure$",
            ".*\\\\Software\\\\Doctor\\ Web$",
            ".*\\\\Software\\\\ESET$",
            ".*\\\\Software\\\\ESET\\\\.*",
            ".*\\\\Software\\\\G\\ Data$",
            ".*\\\\Software\\\\Symantec$",
            ".*\\\\Software\\\\KasperskyLab\\\\.*",
            ".*\\\\Software\\\\McAfee\\\\.*",
            ".*\\\\Software\\\\McAfee\.com\\\\.*",
            ".*\\\\Software\\\\Microsoft\\\\Microsoft\\ Antimalware$",
            ".*\\\\Software\\\\Network\\ Associates\\\\TVD$",
            ".*\\\\Software\\\\Panda\\ Software$",
            ".*\\\\Software\\\\rising$",
            ".*\\\\Software\\\\Softed\\\\ViGUARD$",
            ".*\\\\Software\\\\Sophos$",
            ".*\\\\Software\\\\Sophos\\\\.*",
            ".*\\\\Software\\\\TrendMicro$",
            ".*\\\\Software\\\\VBA32$",
            ".*\\\\Software\\\\Zone\\ Labs\\\\ZoneAlarm$",
        ]
        found = False
        for indicator in reg_indicators:
            reg_match = self.check_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                for match in reg_match:
                    self.data.append({"key" : match })
                found = True
        return found