# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class IMStealer(Signature):
    name = "infostealer_im"
    description = "Harvests information related to installed instant messenger clients"
    severity = 3
    categories = ["infostealer"]
    authors = ["Accuvant"]
    minimum = "1.0"

    def run(self):
        file_indicators = [
            ".*\\\\AIM\\\\aimx\.bin$",
            ".*\\\\Digsby\\\\loginfo\.yaml$",
            ".*\\\\Digsby\\\\Digsby\.dat$",
            ".*\\\\Meebo\\\\MeeboAccounts\.txt$",
            ".*\\\\Miranda\\\\.*\.dat$",
            ".*\\\\MySpace\\\\IM\\\\users\.txt$",
            ".*\\\\\.purple\\\\Accounts\.xml$",
            ".*\\\\Skype\\\\.*\\\\config\.xml$",
            ".*\\\\Tencent\\ Files\\\\.*\\\\QQ\\\\Registry\.db$",
            ".*\\\\Trillian\\\\users\\\\global\\\\accounts\.ini$",
            ".*\\\\Xfire\\\\XfireUser\.ini$"
        ]
        registry_indicators = [
            ".*\\\\Software\\\\America\\ Online\\\\AIM6\\\\Passwords.*",
            ".*\\\\Software\\\\AIM\\\\AIMPRO\\\\.*",
            ".*\\\\Software\\\\Beyluxe\\ Messenger\\\\.*",
            ".*\\\\Software\\\\BigAntSoft\\\\BigAntMessenger\\\\.*",
            ".*\\\\Software\\\\Camfrog\\\\Client\\\\.*",
            ".*\\\\Software\\\\Google\\\\Google\\ Talk\\\\Accounts\\\\.*",
            ".*\\\\Software\\\\IMVU\\\\.*",
            ".*\\\\Software\\\\Nimbuzz\\\\PCClient\\\\Application\\\\.*",
            ".*\\\\Software\\\\Paltalk\\\\.*",
            ".*\\\\Software\\\\Yahoo\\\\Pager\\\\.*"
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
