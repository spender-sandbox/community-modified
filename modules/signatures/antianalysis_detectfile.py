# Copyright (C) 2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AntiAnalysisDetectFile(Signature):
    name = "antianalysis_detectfile"
    description = "Attempts to identify installed analysis tools by a known file location"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["KillerInstinct"]
    minimum = "1.2"

    def run(self):
        file_indicators = [
            "^[A-Za-z]:\\\\analysis",
            "^[A-Za-z]:\\\\iDEFENSE",
            "^[A-Za-z]:\\\\popupkiller.exe$",
            "^[A-Za-z]:\\\\tools\\\\execute.exe$",
            "^[A-Za-z]:\\\\Program\\ Files(\\ \(x86\))?\\\\Fiddler",
            "^[A-Za-z]:\\\\ComboFix",
        ]
        ret = False
        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True, all=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file" : match })
                ret = True
        return ret
