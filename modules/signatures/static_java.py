from lib.cuckoo.common.abstracts import Signature

class Static_Java(Signature):
    name = "static_java"
    description = "JAR file contains suspicious characteristics"
    severity = 2
    weight = 0
    reflection = 0
    categories = ["java", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    def run(self):

        # https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-a-daily-grind-filtering-java-vulnerabilities.pdf, https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-java-vulnerabilities.pdf, https://www.virusbtn.com/virusbulletin/archive/2013/06/vb201306-Java-null 

        functions = [".invoke(",".getMethod(","class.forName(",".getClass(",".getField(",".getConstructor(",".newInstance("]
        permissions = ["setSecurityManager","getSecurityManager","doPrivileged","AllPermission"]

        if "static" in self.results and "java" in self.results["static"]:
            if "java" in self.results["static"]:
                if "decompiled" in self.results["static"]["java"]:
                    decompiled = self.results["static"]["java"]["decompiled"]
                    for functions in functions:
                        self.reflection += decompiled.count(functions)    
                    if self.reflection > 0:           
                        self.data.append({"obfuscation_reflection" : "Contains %s occurances of potential Java reflection indirect function call obfuscation" % (self.reflection)})
                	self.weight += 1

                    for permissions in permissions:
                        if permissions in decompiled:
                           self.data.append({"security_permissions" : "Contains %s potentially used to modify the security level" % (permissions)})
                           self.severity = 3
                	   self.weight += 1

                    if "URL(" in decompiled or "URLEncoder.encode(" in decompiled or "openConnection(" in decompiled:
                        self.data.append({"http" : "Contains ability to make HTTP connections" })
                	self.weight += 1

                    if ".exec(" in decompiled or ".getRuntime(" in decompiled:
                        self.data.append({"execute" : "Contains ability to run executable code" })
                        self.severity = 3
                	self.weight += 1

                    # Specific Exploit Detections
                    # http://research.zscaler.com/2014/07/dissecting-cve-2013-2460-java-exploit.html
                    if "ProviderFactory" in decompiled and "getDefaultFactory" in decompiled:
                        self.description += " and contains possible exploit code."
                        self.data.append({"cve_2013-2460" : "ProviderSkeleton Insecure Invoke Method exploit code" })
                        self.severity = 3
                	self.weight += 1
                    # http://malware.dontneedcoffee.com/2013/08/cve-2013-2465-integrating-exploit-kits.html
                    if "SinglePixelPackedSampleModel" in decompiled or "MultiPixelPackedSampleModel" in decompiled:
                        self.description += " and contains possible exploit code."
                        self.data.append({"cve_2013-2465" : "storeImageArray Invalid Array Indexing exploit code" })
                        self.severity = 3
                	self.weight += 1

        if self.weight:
            return True
        return False
