# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature
import struct

class StealthFile(Signature):
    name = "stealth_file"
    description = "Creates a hidden or system file"
    severity = 3
    categories = ["stealth"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    BasicFileInformation = 4

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.handles = dict()
        self.lastprocess = 0
        self.stealth_files = []

    filter_apinames = set(["NtCreateFile", "NtDuplicateObject", "NtOpenFile", "NtClose", "NtSetInformationFile"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if call["api"] == "NtDuplicateObject" and call["status"]:
            tgtarg = self.get_argument(call, "TargetHandle")
            if tgtarg:
                srchandle = int(self.get_argument(call, "SourceHandle"), 16)
                tgthandle = int(tgtarg, 16)
                if srchandle in self.handles:
                    self.handles[tgthandle] = self.handles[srchandle]
        elif (call["api"] == "NtOpenFile" or call["api"] == "NtCreateFile") and call["status"]:
                handle = int(self.get_argument(call, "FileHandle"), 16)
                filename = self.get_argument(call, "FileName")
                if handle not in self.handles:
                        self.handles[handle] = filename
        elif call["api"] == "NtClose":
                handle = int(self.get_argument(call, "Handle"), 16)
                self.handles.pop(handle, None)
        if call["api"] == "NtCreateFile" and call["status"]:
            disp = int(self.get_argument(call, "CreateDisposition"), 10)
            attrib = int(self.get_argument(call, "FileAttributes"), 16)
            # FILE_OPEN / FILE_OPEN_IF
            if disp != 1 and disp != 3:
                # SYSTEM or HIDDEN
                if attrib & 4 or attrib & 2:
                    filename = self.get_argument(call, "FileName")
                    if filename not in self.stealth_files:
                        self.stealth_files.append(filename)
        elif call["api"] == "NtSetInformationFile":
            handle = int(self.get_argument(call, "FileHandle"), 16)
            settype = int(self.get_argument(call, "FileInformationClass"), 10)
            if settype == self.BasicFileInformation:
                attrib = 0
                try:
                    crt, lat, lwt, cht, attrib = struct.unpack_from("QQQQI", self.get_raw_argument(call, "FileInformation"))
                except:
                    pass
                if attrib & 4 or attrib & 2:
                    if handle in self.handles:
                        if self.handles[handle] not in self.stealth_files:
                            self.stealth_files.append(self.handles[handle])
                    else:
                        if "UNKNOWN" not in self.stealth_files:
                            self.stealth_files.append("UNKNOWN")

        return None

    def on_complete(self):
        whitelists = [
            r'^[A-Z]?:\\Documents and Settings\\[^\\]+\\Local Settings\\Temporary Internet Files$',
            r'^[A-Z]?:\\Documents and Settings\\[^\\]+\\Local Settings\\History$',
            r'^[A-Z]?:\\Documents and Settings\\[^\\]+\\Local Settings\\Temporary Internet Files\\Content\.IE5\\$',
            r'^[A-Z]?:\\Documents and Settings\\[^\\]+\\Local Settings\\History\\History\.IE5\\$',
            r'^[A-Z]?:\\Documents and Settings\\[^\\]+\\Local Settings\\History\\History\.IE5\\MSHist[0-9]+\\$',
            r'^[A-Z]?:\\Documents and Settings\\[^\\]+\\Local Settings\\History\\History\.IE5\\MSHist[0-9]+\\index\.dat$',
            r'^[A-Z]?:\\Documents and Settings\\[^\\]+\\Cookies\\$',
            r'^[A-Z]?:\\Users\\[^\\]+\\Favorites\\Links\\.*',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Feeds\\.*',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Feeds Cache\\$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Feeds Cache\\index\.dat$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\IETldCache\\$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\IETldCache\\index\.dat$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\IECompatCache\\$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\IECompatCache\\index.dat$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\PrivacIE\\$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\PrivacIE\\index\.dat$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Internet Explorer\\DOMStore\\$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Internet Explorer\\DOMStore\\.*',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\History\\History\.IE5\\$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\History\\History\.IE5\\MSHist[0-9]+\\$',
            r'^[A-Z]?:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\History\\History\.IE5\\MSHist[0-9]+\\index\.dat$',
        ]
        saw_stealth = False
        target_name = None

        if "file" in self.results["target"] and "PE32" not in self.results["target"]["file"]["type"]:
            target_name = self.results["target"]["file"]["name"]
            
        for hfile in self.stealth_files:
            addit = True
            for entry in whitelists:
                if re.match(entry, hfile, re.IGNORECASE):
                    addit = False

            if target_name and not hfile.endswith("\\"):
                fname = hfile.split("\\")[-1][2:]
                if fname == target_name or fname in target_name:
                    addit = False

            if addit:
                saw_stealth = True
                self.data.append({"file" : hfile})

        return saw_stealth

