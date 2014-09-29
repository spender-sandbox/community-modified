# Copyright (C) 2012 Michael Boman (@mboman)
#
# This program is free Software: you can redistribute it and/or modify
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

# Based on information from http://antivirus.about.com/od/windowsbasics/tp/autostartkeys.htm

# Additional keys added from SysInternals Administrators Guide

from lib.cuckoo.common.abstracts import Signature

class Autorun(Signature):
    name = "persistence_autorun"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman", "nex","securitykitten"]
    minimum = "1.2"

    def run(self):
        indicators = [
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Notify\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run\\\\.*",
            ".*\\\\Microsoft\\\\Active\\ Setup\\\\Installed Components\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_DLLs$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\SharedTaskScheduler\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\[^\\\\]*\\\\\Debugger$",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell$",
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\ImagePath$",
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\ServiceDLL$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Exefile\\\\Shell\\\\Open\\\\Command\\\\\(Default\)$",
            ".*\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\load$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad\\\\.*"
        ]

        for indicator in indicators:
            match_key = self.check_write_key(pattern=indicator, regex=True)
            if match_key:
                self.data.append({"key" : match_key})
                return True

        indicators = [
            ".*\\\\win\.ini$",
            ".*\\\\system\.ini$",
            ".*\\\\Start Menu\\\\Programs\\\\Startup\\\\.*",
            ".*\\\\WINDOWS\\\\Tasks\\\\.*"
        ]

        for indicator in indicators:
            match_file = self.check_write_file(pattern=indicator, regex=True)
            if match_file:
                self.data.append({"file" : match_file})
                return True

        return False
