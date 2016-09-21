from lib.cuckoo.common.abstracts import Signature

class RansomwareExtensions(Signature):
    name = "ransomware_extensions"
    description = "Appends known ransomware file extensions to files that have been encrypted"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        indicators = [
            ".*\.aaa$",
            ".*\.abc$",
            ".*\.ccc$",
            ".*\.ecc$",
            ".*\.exx$",
            ".*\.ezz$",
            ".*\.vvv$",
            ".*\.rdm$",
            ".*\.rrk$",
            ".*\.toxcrypt$",
            ".*\.vault$",
            ".*\.hydracrypt_ID_[a-z0-9]{8}$",
            ".*\.hydracrypttmp_ID_[a-z0-9]{8}$",
            ".*\.micro$",
            ".*\.locky$",
            ".*\.xtbl$",
            ".*\.crypt$",
            ".*\.locked$",
            ".*\.cerber$",
            ".*\.cerber2$",
            ".*\.cerber3$",
            ".*\.encrypt$",
            ".*\.R5A$",
            ".*\.R4A$",
            ".*\.herbst$",
            ".*\.CrySiS$",
            ".*\.bart\.zip$",
            ".*\.zepto$",
            ".*\.wflx$",
            ".*\.id_[^\/]*\.scl$",
            ".*\.razy$",
            ".*\.Venus(f|p)$",
            ".*\.crypz$",
            ".*\.cryp1$",
            ".*\.fs0ciety",
            ".*\.cry",
            ".*\.locked",
            ".*\.locklock",
            ".*\.fantom",
        ]

        for indicator in indicators:
            results = self.check_write_file(pattern=indicator, regex=True, all=True)
            if results and len(results) > 15:
                return True

        return False
