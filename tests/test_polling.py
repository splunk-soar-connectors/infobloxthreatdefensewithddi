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

import unittest

from infoblox_polling import next_poll_start, parse_event_timestamp


class PollingCheckpointTest(unittest.TestCase):
    def test_next_poll_retries_last_successful_second(self):
        successful = parse_event_timestamp("2026-07-14T12:00:00.100Z")
        failed = parse_event_timestamp("2026-07-14T12:00:00.900Z")

        self.assertEqual(successful, failed)
        self.assertEqual(next_poll_start(successful), failed)

    def test_next_poll_does_not_advance_to_the_following_second(self):
        checkpoint = parse_event_timestamp("2026-07-14T12:00:00.999Z")
        self.assertEqual(next_poll_start(checkpoint), checkpoint)
        self.assertNotEqual(next_poll_start(checkpoint), checkpoint + 1)
