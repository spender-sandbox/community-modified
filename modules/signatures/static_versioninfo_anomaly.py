# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VersionInfoAnomaly(Signature):
    name = "static_versioninfo_anomaly"
    description = "Inconsistent version info supplied for binary"
    severity = 3
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        found_sig = False

        if not "static" in self.results or not "pe_versioninfo" in self.results["static"]:
            return False

        msincopyright = False
        msincompanyname = False
        for info in self.results["static"]["pe_versioninfo"]:
            if info["name"] == "LegalCopyright":
                if "microsoft" in info["value"].lower():
                    msincopyright = True
                else:
                    msincopyright = False
            elif info["name"] == "CompanyName":
                if "microsoft" in info["value"].lower():
                    msincompanyname = True
                else:
                    msincompanyname = False

        if msincopyright == True and msincompanyname == False:
            self.data.append({"anomaly" : "Microsoft mentioned in LegalCopyright, but not in CompanyName field"})
            found_sig = True

        return found_sig
