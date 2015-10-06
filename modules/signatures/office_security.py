from lib.cuckoo.common.abstracts import Signature

class OfficeSecurity(Signature):
    name = "office_security"
    description = "Attempts to modify Microsoft Office security settings"
    severity = 3
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        reg_indicators = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Office\\\\.*\\\\Security\\\\.*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Office\\\\.*\\\\Security\\\\.*",    
        ]

        for indicator in reg_indicators:
            if self.check_write_key(pattern=indicator, regex=True):
                return True

        return False
