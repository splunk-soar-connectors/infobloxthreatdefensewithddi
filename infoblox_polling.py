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

from datetime import datetime, timezone


def parse_event_timestamp(event_time: str) -> int:
    """Return the whole-second event timestamp used by the upstream query API."""
    parsed = datetime.strptime(event_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    return int(parsed.replace(tzinfo=timezone.utc).timestamp())


def next_poll_start(last_event_time: int) -> int:
    """Retry the last successful second so later same-second events are not skipped."""
    return int(last_event_time)
