#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# StackExchange Ocean feeder
#
# Copyright (C) 2015 Bitergia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# Authors:
#   Alvaro del Castillo San Felix <acs@bitergia.com>
#

import datetime
from grimoire.ocean.elastic import ElasticOcean

class StackExchangeOcean(ElasticOcean):
    """StackExchange Ocean feeder"""

    def __init__(self, perceval_backend, cache = False,
                 incremental = True, **nouse):
        super(StackExchangeOcean, self).__init__(perceval_backend)

    def get_field_unique_id(self):
        return "question_id"

    def get_field_date(self):
        return "__metadata__updated_on"

    def add_update_date(self, item):
        entry_lastUpdated = datetime.datetime.fromtimestamp(item['__metadata__']['updated_on'])
        item['__metadata__updated_on'] = entry_lastUpdated.isoformat()
