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
            "ec7e6f5458456dddb2d826bf1b8b03a2",
            # PDF icon
            "6890c8a40c2eb5ff973159eca0428d6e",
            "2c45339aea71418c49248aa88ffb2378",
            "059dcdf32e800b5f2fe2aea2d5f045d8",
            "9334967a316ffffd255aaf9224a7da5e",
            "e52d1e9d64fd9535bf10f6da1091df9d",
            "b686a61a6fbd20073faf430128597795",
            
        ]

        if "static" in self.results and "pe" in self.results["static"]  and "icon_fuzzy" in self.results["static"]["pe"]:
            if self.results["static"]["pe"]["icon_fuzzy"] in badhashes:
                return True
        return False
