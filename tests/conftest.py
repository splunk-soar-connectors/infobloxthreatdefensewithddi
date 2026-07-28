# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import importlib.util
import sys
import types
from pathlib import Path


if importlib.util.find_spec("phantom") is None:
    phantom_package = types.ModuleType("phantom")
    phantom_package.__path__ = []
    phantom_app = types.ModuleType("phantom.app")
    phantom_app.APP_SUCCESS = 0
    phantom_app.APP_ERROR = 1
    phantom_action_result = types.ModuleType("phantom.action_result")
    phantom_action_result.ActionResult = object
    phantom_package.app = phantom_app
    phantom_package.action_result = phantom_action_result
    sys.modules["phantom"] = phantom_package
    sys.modules["phantom.app"] = phantom_app
    sys.modules["phantom.action_result"] = phantom_action_result

# encryption_helper is provided by the SOAR platform at runtime and is not installable,
# so stub it for offline test collection.
if importlib.util.find_spec("encryption_helper") is None:
    encryption_helper_module = types.ModuleType("encryption_helper")
    encryption_helper_module.encrypt = lambda value, key: value
    encryption_helper_module.decrypt = lambda value, key: value
    sys.modules["encryption_helper"] = encryption_helper_module

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
