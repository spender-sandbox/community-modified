from lib.cuckoo.common.abstracts import Signature

class FamilyRadamant(Signature):
    name = "family_radamant"
    description = "Exhibits behavior characteristics of Radamant ransomware"
    severity = 3
    families = ["radamant"]
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        mutexes = [
            "Radamant_v.*",
            ".*radamantv.*",
        ]

        for mutexes in mutexes:
            if self.check_mutex(pattern=mutexes, regex=True):
                return True

        # Check for creation of Autorun
        if self.check_write_key(pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\(svchost|DirectX)$", regex=True) and self.check_write_file(pattern=".*\\\\Windows\\\\dirextx.exe$", regex=True):
            return True

        # Check for creation of ransom message file
        if self.check_write_file(pattern=".*\\\\YOUR_FILES.url$", regex=True):
            return True

        return False
