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

from lib.cuckoo.common.abstracts import Signature

class Ursnif_APIs(Signature):
    name = "ursnif_behavior"
    description = "Exhibits behavior characteristics of Ursnif spyware"
    severity = 3
    weight = 3
    categories = ["spyware", "keylogger"]
    families = ["ursnif"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    def run(self):
        badness = 0
        cmdpat = r"^[A-Za-z]:\\.*\\[0-9A-Fa-f]{4}\\[0-9A-Fa-f]{4}\.bat\s"
        if self.check_executed_command(pattern=cmdpat, regex=True):
            arg1, arg2 = None, None
            for command in self.results["behavior"]["summary"]["executed_commands"]:
                if len(command.split()) == 3 and ".bat" in command.split()[0][-5:]:
                    _, arg1, arg2 = command.split()
                else:
                    if command.replace(" ", "").lower().startswith("cmd/c") and arg1 and arg2:
                        buf = command.split()
                        if len(buf) == 4:
                            if arg1 in buf[2] and arg2 in buf[3]:
                                badness += 8
                    else:
                        pass

        keypat = r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\EnableSPDY3_0$"
        if self.check_write_key(pattern=keypat, regex=True):
            badness += 2

        mutexpat = r"(?:Local\\)?\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}"
        mutexes = self.check_mutex(pattern=mutexpat, regex=True, all=True)
        if mutexes:
            mutex_count = len(mutexes)
            if mutex_count >= 2:
                badness += 2
            else:
                badness += mutex_count

        if badness >= 10:
            return True

        return False
