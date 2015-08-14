# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MimicsIcon(Signature):
    name = "mimics_icon"
    description = "Mimics icon used for popular non-executable file format"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.3"

    def run(self):
        badhashes = [
            # newer word doc icon
            "2ebf2847d2a3c24ba843a2a51b716db3",
        ]

        if "static" in self.results and "pe_icon_fuzzy" in self.results["static"]:
            if self.results["static"]["pe_icon_fuzzy"] in badhashes:
                return True
        return False
