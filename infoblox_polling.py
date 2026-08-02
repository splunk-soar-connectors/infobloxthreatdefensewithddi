from datetime import datetime, timezone


def parse_event_timestamp(event_time: str) -> int:
    """Return the whole-second event timestamp used by the upstream query API."""
    parsed = datetime.strptime(event_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    return int(parsed.replace(tzinfo=timezone.utc).timestamp())


def next_poll_start(last_event_time: int) -> int:
    """Retry the last successful second so later same-second events are not skipped."""
    return int(last_event_time)
