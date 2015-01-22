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
            ".*\\\\Software\\\\BitDefender\\\\.*",
            ".*\\\\Software\\\\ESET\\\\.*",
            ".*\\\\Software\\\\KasperskyLab\\\\.*",
            ".*\\\\Software\\\\McAfee\\\\.*",
            ".*\\\\Software\\\\McAfee\.com\\\\.*",
            ".*\\\\Software\\\\Sophos\\\\.*",
        ]
        found = False
        for indicator in reg_indicators:
            reg_match = self.check_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                for match in reg_match:
                    self.data.append({"key" : match })
                found = True
        return found