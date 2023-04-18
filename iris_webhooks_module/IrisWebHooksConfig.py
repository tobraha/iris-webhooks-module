#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2022 - DFIR-IRIS Team
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

module_name = "IrisWebHooks"
module_description = "Provides webhooks for IRIS. See https://docs.dfir-iris.org/operations/modules/natives/IrisWebHooks/"
interface_version = "1.2.0"
module_version = "1.0.3.1"
pipeline_support = False
pipeline_info = {}

module_configuration = [
    {
        "param_name": "wh_configuration",
        "param_human_name": "Webhooks configuration",
        "param_description": "JSON Webhooks configuration",
        "default": "{}",
        "mandatory": True,
        "type": "textfield_json"
    }
]

