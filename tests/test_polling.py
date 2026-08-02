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
