# Copyright (C) 2010-2015 KillerInstinct
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

from lib.cuckoo.common.abstracts import Feed

class Punch_Plus_Plus_PCREs(Feed):
    name = "Punch_Plus_Plus_PCREs"
    enabled = False

    def __init__(self):
        Feed.__init__(self)
        # It was reqested that I leave the API key blank and to add a note that
        # if you would like to use the service, to contact Nathan Fowler for an
        # API key.
        apikey = ""
        self.downloadurl = "https://punchplusplus.miscreantpunchers.net/feeds" \
                           ".php?feed=pcres.txt&apikey=" + apikey
        self.feedname = "punch_plus_plus_pcres"
        # Number of hours to wait before checking for an update
        self.frequency = 6
