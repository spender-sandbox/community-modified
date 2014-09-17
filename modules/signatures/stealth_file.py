# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthFile(Signature):
    name = "stealth_file"
    description = "Creates a hidden or system file"
    severity = 3
    categories = ["stealth"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.handles = dict()
        self.saw_stealth = False

    filter_apinames = set(["NtCreateFile", "NtDuplicateObject", "NtOpenFile", "NtClose", "NtSetInformationFile"])

    def on_call(self, call, process):
        if call["api"] == "NtDuplicateObject" and call["status"]:
            srchandle = int(self.get_argument(call, "SourceHandle"), 16)
            tgthandle = int(self.get_argument(call, "TargetHandle"), 16)
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
                    self.saw_stealth = True
                    filename = self.get_argument(call, "FileName")
                    self.data.append({"file" : filename })
        elif call["api"] == "NtSetInformationFile":
            handle = int(self.get_argument(call, "FileHandle"), 16)
            crt, lat, lwt, cht, attrib = struct.unpack_from("QQQQI", self.get_raw_argument(call, "FileInformation"))
            if attrib & 4 or attrib & 2:
                self.saw_stealth = True
                if handle in self.handles:
                    self.data.append({"file" : self.handles[handle]})
                else:
                    self.data.append({"file" : "UNKNOWN"})

        return None

    def on_complete(self):
        if self.saw_stealth:
            return True
        return False