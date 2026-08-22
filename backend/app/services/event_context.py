from dataclasses import dataclass


@dataclass
class EventContext:
    event_count: int
    recent_event_count: int
    failed_login_count: int
    unique_username_count: int