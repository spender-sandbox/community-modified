# Copyright (C) 2016 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class APISpamming(Signature):
    name = "api_spamming"
    description = "Attempts to repeatedly call a single API many times in order to delay analysis time"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    def run(self):
        ret = False
        if self.results.get("behavior", {}).get("processes", []):
            for process in self.results["behavior"]["processes"]:
                if process.get("spam_apis", []):
                    ret = True
                    for spam in process["spam_apis"]:
                        self.data.append({"Spam": "{0} ({1}) called API {2} {3} times".format(
                            spam["name"], spam["pid"], spam["api"], spam["count"])})
        return ret
