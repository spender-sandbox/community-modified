# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Authenticode(Signature):
    name = "static_authenticode"
    description = "Presents an Authenticode digital signature"
    severity = 1
    categories = ["static"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        if "static" in self.results:
            if "pe_dirents" in self.results["static"]:
                for entry in self.results["static"]["pe_dirents"]:
                    if entry["name"] == "IMAGE_DIRECTORY_ENTRY_SECURITY" and entry["virtual_address"] != "0x00000000" and entry["size"] != "0x00000000":
                        return True
        return False