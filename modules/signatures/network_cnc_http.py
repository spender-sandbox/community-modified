try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class NetworkCnCHTTP(Signature):
    name = "network_cnc_http"
    description = "HTTP traffic contains suspicious features which may be indicative of malware related traffic"
    severity = 2
    confidence = 30
    weight = 0
    categories = ["http", "cnc"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):

        whitelist = [
            "^http://.*\.microsoft\.com/.*",
            "^http://.*\.windowsupdate\.com/.*",
            "http://.*\.adobe\.com/.*",
            ]

        # HTTP request Features. Done like this due to for loop appending data each time instead of once so we wait to end of checks to add summary of anomalies
        post_noreferer = 0
        post_nouseragent = 0
        get_nouseragent = 0
        version1 = 0
        iphost = 0
        offport = 0

        # Scoring
        cnc_score = 0
        suspectrequest = []

        if "network" in self.results and "http" in self.results["network"]:
            for req in self.results["network"]["http"]:
                is_whitelisted = False
                for white in whitelist:
                    if re.match(white, req["uri"], re.IGNORECASE):
                        is_whitelisted = True                              

                # Check HTTP features
                request = req["uri"]
                ip = re.compile("^http\:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                if not is_whitelisted and req["method"] == "POST" and "Referer:" not in req["data"]:
                    post_noreferer += 1
                    cnc_score += 1

                if not is_whitelisted and req["method"] == "POST" and "User-Agent:" not in req["data"]:
                    post_nouseragent += 1
                    cnc_score += 1

                if not is_whitelisted and req["method"] == "GET" and "User-Agent:" not in req["data"]:
                    get_nouseragent += 1

                if not is_whitelisted and req["version"] == "1.0":
                    version1 += 1
                    cnc_score += 1

                if not is_whitelisted and ip.match(request):
                    iphost += 1
                    cnc_score += 1

                if not is_whitelisted and req["port"] != "80":
                    offport += 1
                    cnc_score += 1

                if not is_whitelisted and cnc_score > 0:
                    if suspectrequest.count(request) == 0:
                        suspectrequest.append(request)

        if post_noreferer > 0:
            self.data.append({"post_no_referer" : "HTTP traffic contains a POST request with no referer header" })
            self.weight += 1

        if post_nouseragent > 0:
            self.data.append({"post_no_useragent" : "HTTP traffic contains a POST request with no user-agent header" })
            self.weight += 1

        if get_nouseragent > 0:
            self.data.append({"get_no_useragent" : "HTTP traffic contains a GET request with no user-agent header" })
            self.weight += 1

        if version1 > 0:
            self.data.append({"http_version_old" : "HTTP traffic uses version 1.0" })
            self.weight += 1

        if iphost > 0:
            self.data.append({"ip_hostname" : "HTTP connection was made to an IP address rather than domain name" })
            self.weight += 1

        if offport > 0:
            self.data.append({"non_standard_port" : "HTTP connection was made to port other than port 80" })
            self.weight += 1

        if self.weight and len(suspectrequest) > 0:
            for request in suspectrequest:
                self.data.append({"suspicious_request" : request})

        if self.weight:
            return True

        return False
