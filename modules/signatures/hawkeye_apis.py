# Copyright (C) 2015 KillerInstinct
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

from lib.cuckoo.common.abstracts import Signature

class HawkEye_APIs(Signature):
    name = "hawkeye_behavior"
    description = "Exhibits behavior characteristics of HawkEye keylogger."
    severity = 3
    weight = 3
    categories = ["trojan", "keylogger"]
    families = ["hawkeye"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["send", "WSAConnect", "getaddrinfo"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.badness = 0
        self.sockets = dict()
        self.lastcall = str()
        self.nodename = str()
        self.badsocks = set()
        self.keywords = [
                # SMTP Keywords
                "AUTH",
                "MAIL FROM",
                "RCPT TO",
                # FTP Keywords
                "USER"
        ]

    def on_call(self, call, process):
        if call["api"] == "getaddrinfo":
            buf = self.get_argument(call, "NodeName")
            if buf:
                self.nodename = buf

        elif call["api"] == "WSAConnect":
            if self.lastcall == "getaddrinfo":
                sock = self.get_argument(call, "socket")
                ip = self.get_argument(call, "ip")
                port = self.get_argument(call, "port")
                if sock not in self.sockets.keys():
                    self.sockets[sock] = dict()
                    self.sockets[sock]["conn"] = "%s:%s" % (ip, port)
                    self.sockets[sock]["node"] = self.nodename
                    self.sockets[sock]["data"] = list()

        elif call["api"] == "send":
            buf = self.get_argument(call, "buffer")
            sock = self.get_argument(call, "socket")
            if "hawkeye keylogger" in buf.lower():
                self.badness += 10
            if "dear hawkeye customers" in buf.lower():
                self.badness += 10
            for word in self.keywords:
                if buf.startswith(word):
                    self.sockets[sock]["data"].append(buf)
                    self.badsocks.add(sock)

        self.lastcall = call["api"]


    def on_complete(self):
        if self.check_file(pattern=".*\\\\pid.txt$", regex=True):
            self.badness += 2
        if self.check_file(pattern=".*\\\\pidloc.txt$", regex=True):
            self.badness += 2
        if self.check_file(pattern=".*\\\\holdermail.txt$", regex=True):
            self.badness += 4
        if self.badness > 5:
            # Delete the non-malicious related sockets
            for sock in self.sockets.keys():
                if sock not in self.badsocks:
                    del self.sockets[sock]
            # Parse for indicators
            for sock in self.sockets.keys():
                ioc = {"Host": self.sockets[sock]["conn"]}
                if ioc not in self.data:
                    self.data.append(ioc)
                ioc = {"Hostname": self.sockets[sock]["node"]}
                if ioc not in self.data:
                    self.data.append(ioc)
                for item in self.sockets[sock]["data"]:
                    if "AUTH" in item:
                        buf = item.split()[2].decode("base64")
                        ioc = {"SMTP_Auth_Email": buf}
                        if ioc not in self.data:
                            self.data.append(ioc)
                    elif "MAIL FROM" in item:
                        buf = item.split(":")[1].strip()
                        ioc = {"SMTP_Mail_From": buf}
                        if ioc not in self.data:
                            self.data.append(ioc)
                    elif "RCPT TO" in item:
                        buf = item.split(":")[1].strip()
                        ioc = {"SMTP_Send_To": buf}
                        if ioc not in self.data:
                            self.data.append(ioc)
                    elif "USER" in item:
                        buf = item.split()[1].strip()
                        ioc = {"FTP_User": buf}
                        if ioc not in self.data:
                            self.data.append(ioc)
            return True

        return False
