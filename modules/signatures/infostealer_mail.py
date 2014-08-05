# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class EmailStealer(Signature):
    name = "infostealer_email"
    description = "Harvests information related to installed mail clients"
    severity = 3
    categories = ["infostealer"]
    authors = ["Accuvant"]
    minimum = "1.0"

    def run(self):
        file_indicators = [
            ".*\.pst$",
            ".*\\\\Microsoft\\\\Windows\\ Live\\ Mail.*"
        ]
        registry_indicators = [
            ".*\\\\Software\\\\Clients\\\\Mail.*",
            ".*\\\\Software\\\\Microsoft\\\\Windows\\ Messaging\\ Subsystem\\\\MSMapiApps.*",
            ".*\\\\Software\\\\Microsoft\\\\Windows\\ Messaging\\ Subsystem\\\\Profiles.*",
            ".*\\\\Software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\ Messaging\\ Subsystem\\\\Profiles.*",
            ".*\\\\Software\\\\Microsoft\\\\Office\\\\.*\\\\Outlook\\\\Profiles\\\\Outlook.*",
            ".*\\\\Software\\\\Microsoft\\\\Office\\\\Outlook\\\\OMI\\ Account\\ Manager\\\\Accounts.*",
            ".*\\\\Software\\\\Microsoft\\\\Internet\\ Account\\ Manager\\\\Accounts.*",
            ".*\\\\Software\\\\IncrediMail.*"
        ]

        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True)
            if file_match:
                self.data.append({"file" : file_match })
                return True
        for indicator in registry_indicators:
            key_match = self.check_key(pattern=indicator, regex=True)
            if key_match:
                self.data.append({"key" : key_match })
                return True
        return False
