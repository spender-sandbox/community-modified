from lib.cuckoo.common.abstracts import Signature

class FamilyProxyBack(Signature):
    name = "family_proxyback"
    description = "Exhibits behavior characteristics of Proxyback malware"
    severity = 3
    families = ["proxyback"]
    authors = ["Kevin Ross"]
    references = ["http://researchcenter.paloaltonetworks.com/2015/12/proxyback-malware-turns-user-systems-into-proxies-without-consent/"]
    minimum = "1.2"

    def run(self):
        mutexes = [
            "PB_MAIN_MUTEX_GL_.*",
            "PB_SN_MUTEX_GL_.*",
            "PB_SCH_MUTEX_GL_.*"
        ]

        for mutexes in mutexes:
            if self.check_mutex(pattern=mutexes, regex=True):
                return True

        if "network" in self.results and "http" in self.results["network"]:
            for req in self.results["network"]["http"]:
                if "User-Agent: pb" in req["data"]:
                    return True

        return False
