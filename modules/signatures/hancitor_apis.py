# Copyright (C) 2016 KillerInstinct
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

def getWrittenUrls(data):
    urls = re.findall("(?P<url>https?://[^\|]+)\|", data)
    if urls:
        return urls

    return []

class Hancitor_APIs(Signature):
    name = "hancitor_behavior"
    description = "Exhibits behavior characteristic of Hancitor downloader"
    weight = 3
    severity = 3
    categories = ["downloader"]
    families = ["hancitor", "chanitor", "tordal"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.c2s = []
        self.badPid = 0
        self.currentUrl = str()
        self.found = False
        self.keywords = ["guid", "build", "info", "ip", "type"]
        self.netSequence = 0
        self.suspended = dict()
        self.bufContents = [
            "Cookie:disclaimer_accepted=true",
            "Content-Type: application/x-www-form-urlencoded",
        ]

    filter_apinames = set(["CreateProcessInternalW", "WriteProcessMemory",
                           "RtlDecompressBuffer", "InternetCrackUrlA",
                           "HttpOpenRequestA", "HttpSendRequestA",
                           "InternetReadFile", "NtClose"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            flags = int(self.get_argument(call, "CreationFlags"), 16)
            if flags & 0x4:
                handle = self.get_argument(call, "ProcessHandle")
                self.suspended[handle] = self.get_argument(call, "ProcessId")

        elif call["api"] == "WriteProcessMemory":
            buf = self.get_argument(call, "Buffer")
            if any(string in buf for string in self.bufContents):
                handle = self.get_argument(call, "ProcessHandle")
                if handle in self.suspended:
                    for pHandle in self.suspended:
                        if pHandle == handle:
                            self.badPid = self.suspended[pHandle]
                            break

                    check = getWrittenUrls(buf)
                    if len(check) >= 2:
                        self.c2s = check

        elif call["api"] == "NtClose":
            if call["status"]:
                handle = self.get_argument(call, "Handle")
                if handle in self.suspended:
                    del self.suspended[handle]

        elif call["api"] == "RtlDecompressBuffer":
            buf = self.get_argument(call, "UncompressedBuffer")
            if "Cookie:disclaimer_accepted=true" in buf:
                self.badPid = str(process["process_id"])
                check = getWrittenUrls(buf)
                if len(check) >= 2:
                    self.c2s = check

        elif call["api"] == "InternetCrackUrlA":
            if process["process_id"] == self.badPid and self.netSequence == 0:
                if call["status"]:
                    self.currentUrl = self.get_argument(call, "Url")
                    self.netSequence += 1

        elif call["api"] == "HttpOpenRequestA":
            if process["process_id"] == self.badPid and self.netSequence == 1:
                if call["status"]:
                    method = self.get_argument(call, "Verb")
                    if method and method == "POST":
                        self.netSequence += 1

        elif call["api"] == "HttpSendRequestA":
            if process["process_id"] == self.badPid and self.netSequence == 2:
                pData = self.get_argument(call, "PostData")
                if pData and all(word in pData for word in self.keywords):
                    self.found = True
                    c2 = {"C2": self.currentUrl}
                    if c2 not in self.data:
                        self.data.append(c2)
                self.netSequence = 0

        elif call["api"] == "InternetReadFile":
            if call["status"] and str(process["process_id"]) == self.badPid:
                buf = self.get_argument(call, "Buffer")
                if buf and buf.startswith("{") and buf.strip().endswith("}"):
                    check = re.findall(":(?P<url>https?://[^\}]+)\}", buf)
                    if check:
                        self.c2s += check

        return None

    def on_complete(self):
        ret = self.found
        if self.c2s:
            ret = True
            for url in self.c2s:
                c2 = {"C2": url}
                if url not in self.data:
                    self.data.append(c2)

        return ret
