"""
Minimal cron expressions for the scheduled analysis (no extra dependency).

Five fields, the same syntax Semaphore's schedules use:

    minute  hour  day-of-month  month  day-of-week
    0-59    0-23  1-31          1-12   0-7 (0 and 7 = Sunday)

Each field accepts *, a value, a range (a-b), a step (*/n, a-b/n) and
comma-separated lists of those. Month and weekday names (jan, mon...) work
too. As in Vixie cron, when both day-of-month and day-of-week are
restricted, a day matches if EITHER of them matches.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from zoneinfo import ZoneInfo


def resolve_tz(name: str) -> tzinfo:
    """Time zone by IANA name. UTC works even without a tz database (slim images)."""
    if name.strip().upper() in ("UTC", "Z", "ETC/UTC", "GMT"):
        return UTC
    return ZoneInfo(name.strip())


_MONTHS = {name: i for i, name in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}
_WEEKDAYS = {name: i for i, name in enumerate(["sun", "mon", "tue", "wed", "thu", "fri", "sat"])}

# (low, high, names) per field
_FIELDS = (
    (0, 59, {}),
    (0, 23, {}),
    (1, 31, {}),
    (1, 12, _MONTHS),
    (0, 7, _WEEKDAYS),
)


def _value(token: str, low: int, high: int, names: dict[str, int]) -> int:
    token = token.strip().lower()
    if token in names:
        return names[token]
    if not token.isdigit():
        raise ValueError(f"'{token}' is not a number")
    number = int(token)
    if not low <= number <= high:
        raise ValueError(f"{number} is outside {low}-{high}")
    return number


def _parse_field(text: str, low: int, high: int, names: dict[str, int]) -> frozenset[int]:
    values: set[int] = set()
    for part in text.split(","):
        if not part:
            raise ValueError("empty list item")
        base, _, step_text = part.partition("/")
        step = 1
        if step_text:
            if not step_text.isdigit() or int(step_text) == 0:
                raise ValueError(f"bad step '{step_text}'")
            step = int(step_text)
        if base == "*":
            start, end = low, high
        elif "-" in base:
            a, _, b = base.partition("-")
            start, end = _value(a, low, high, names), _value(b, low, high, names)
            if start > end:
                raise ValueError(f"range '{base}' goes backwards")
        else:
            start = _value(base, low, high, names)
            # "5/15" means 5, 20, 35, 50 (to the end of the range), as in cron.
            end = high if step_text else start
        values.update(range(start, end + 1, step))
    return frozenset(values)


@dataclass(frozen=True)
class CronSchedule:
    expression: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]  # 0 = Sunday ... 6 = Saturday
    days_restricted: bool
    weekdays_restricted: bool

    @classmethod
    def parse(cls, expression: str) -> CronSchedule:
        parts = expression.split()
        if len(parts) != 5:
            raise ValueError(
                f"cron expression '{expression}' must have 5 fields "
                "(minute hour day month weekday)"
            )
        parsed = []
        for text, (low, high, names) in zip(parts, _FIELDS, strict=True):
            try:
                parsed.append(_parse_field(text, low, high, names))
            except ValueError as exc:
                raise ValueError(f"cron field '{text}': {exc}") from exc
        minutes, hours, days, months, weekdays = parsed
        weekdays = frozenset(d % 7 for d in weekdays)  # 7 is Sunday too
        return cls(
            expression=" ".join(parts),
            minutes=minutes,
            hours=hours,
            days=days,
            months=months,
            weekdays=weekdays,
            days_restricted=parts[2] != "*",
            weekdays_restricted=parts[4] != "*",
        )

    def _day_matches(self, moment: datetime) -> bool:
        if moment.month not in self.months:
            return False
        dom = moment.day in self.days
        dow = (moment.weekday() + 1) % 7 in self.weekdays  # Python: Monday = 0
        if self.days_restricted and self.weekdays_restricted:
            return dom or dow
        return dom and dow

    def matches(self, moment: datetime) -> bool:
        return (
            moment.minute in self.minutes
            and moment.hour in self.hours
            and self._day_matches(moment)
        )

    def next_after(self, moment: datetime, tz: tzinfo) -> datetime:
        """First matching minute strictly after `moment`, as an aware datetime in `tz`."""
        local = moment.astimezone(tz)
        for day_offset in range(0, 5 * 366):  # covers Feb 29 schedules
            day = (local + timedelta(days=day_offset)).date()
            probe = datetime(day.year, day.month, day.day, tzinfo=tz)
            if not self._day_matches(probe):
                continue
            for hour in sorted(self.hours):
                for minute in sorted(self.minutes):
                    candidate = datetime(day.year, day.month, day.day, hour, minute, tzinfo=tz)
                    if candidate > local:
                        return candidate
        raise ValueError(f"cron expression '{self.expression}' never matches")
