#!/usr/bin/env python3
"""ISPConfig helpers for ispconfig_check.yml and ispconfig_update.yml.

Standard library only: it runs on the controller (version comparison) and on
the ISPConfig hosts (building the answers file for update.php).

    ispconfig_autoupdate.py compare 3.3.2p1 3.3.3p2
        prints "older", "same" or "newer" (the first against the second)

    ispconfig_autoupdate.py ini --sample docs/autoinstall_samples/autoinstall.ini.sample \
                                --out /tmp/x/autoupdate.ini --answers '{"reconfigure_services": true}'
        writes the [update] section for "php -q update.php --autoinstall=<file>"

Why the answers file is built from the sample that comes in the tar.gz:
update.php reads each answer by key, and a key it doesn't find, or a value it
doesn't expect, sends it back to an interactive prompt. With no terminal that
prompt loops forever (ISPConfig issue 6601: "n" instead of "no" hung the
updater at 100% CPU). So every key comes from the sample of the version being
installed, every yes/no keeps the spelling the sample uses (yes/no or y/n),
and an answer for a key the sample doesn't have is an error, not a guess.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:(b|rc|p)(\d+))?$")
# Order of the suffixes: beta < release candidate < release < patch release.
_SUFFIX_RANK = {"b": 0, "rc": 1, "": 2, "p": 3}

# Values update.php accepts for its yes/no questions, by spelling.
_LONG = {"yes", "no"}
_SHORT = {"y", "n"}

# Keys that are not yes/no. "default" makes update.php take the value it
# would offer at the prompt (the MariaDB root password from
# mysql_clientdb.conf, the current panel port), so no secret is written here.
DEFAULT_KEYS = {
    "mysql_root_password", "mysql_master_hostname", "mysql_master_port",
    "mysql_master_root_user", "mysql_master_root_password", "mysql_master_database",
    "ispconfig_port",
}


# Characters that end or change a value in an INI line: ";" and "#" start a
# comment (the rest of the answer is lost and update.php may fall back to a
# prompt), quotes and "=" are parsed by the INI reader, "[" and "]" look like
# a section. Values are short tokens ("default", a port, a hostname).
_BAD_VALUE_CHARS = set(';#"\'=[]')


class IniError(ValueError):
    pass


def version_key(version: str) -> tuple:
    """Sortable key for ISPConfig versions: 3.3.1b1 < 3.3.1 < 3.3.1p1 < 3.3.2."""
    m = VERSION_RE.match(version.strip())
    if not m:
        raise ValueError(f"not an ISPConfig version: {version!r}")
    numbers = tuple(int(n) for n in m.group(1).split("."))
    # 3.3 and 3.3.0 are the same version.
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers = numbers[:-1]
    suffix = m.group(2) or ""
    return numbers, _SUFFIX_RANK[suffix], int(m.group(3) or 0)


def compare(a: str, b: str) -> str:
    ka, kb = version_key(a), version_key(b)
    return "older" if ka < kb else "newer" if ka > kb else "same"


def update_section(sample: str) -> list[tuple[str, str]]:
    """(key, value) pairs of the [update] section of an autoinstall.ini sample."""
    pairs: list[tuple[str, str]] = []
    inside = False
    for raw in sample.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            inside = line[1:-1].strip().lower() == "update"
            continue
        if not inside or not line or line.startswith((";", "#")) or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key:
            pairs.append((key, value))
    if not pairs:
        raise IniError("the sample has no [update] section")
    return pairs


def _flag(value: bool, sample_value: str, key: str) -> str:
    if sample_value.lower() in _LONG:
        return "yes" if value else "no"
    if sample_value.lower() in _SHORT:
        return "y" if value else "n"
    raise IniError(f"{key}: the sample value {sample_value!r} is not yes/no or y/n")


def build_ini(sample: str, answers: dict[str, object]) -> str:
    """
    The [update] section with the given answers.

    answers: key -> bool for yes/no questions, or a string ("default" or a
    value) for the others. Keys in DEFAULT_KEYS that are not answered get
    "default"; the remaining yes/no keys keep the sample's value, which is the
    behaviour update.php documents for them.
    """
    pairs = update_section(sample)
    keys = [k for k, _ in pairs]
    unknown = sorted(set(answers) - set(keys))
    if unknown:
        raise IniError(f"keys not in this version's sample: {', '.join(unknown)}")
    out = ["[update]"]
    for key, sample_value in pairs:
        if key in answers:
            value = answers[key]
            if isinstance(value, bool):
                text = _flag(value, sample_value, key)
            else:
                text = str(value)
                if not text or "\n" in text or "\r" in text:
                    raise IniError(f"{key}: empty or multi-line value")
                if _BAD_VALUE_CHARS & set(text) or not text.isprintable() or text != text.strip():
                    raise IniError(f"{key}: the value can't contain ; # quotes = [ ] or surrounding spaces")
                if sample_value.lower() in _LONG | _SHORT and text.lower() not in (
                        _LONG if sample_value.lower() in _LONG else _SHORT) | {"default"}:
                    raise IniError(f"{key}: {text!r} doesn't match the sample's spelling ({sample_value})")
        elif key in DEFAULT_KEYS:
            text = "default"
        else:
            text = sample_value
        out.append(f"{key}={text}")
    return "\n".join(out) + "\n"


def _cmd_compare(args: argparse.Namespace) -> int:
    try:
        print(compare(args.a, args.b))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


def _cmd_ini(args: argparse.Namespace) -> int:
    try:
        answers = json.loads(args.answers)
        if not isinstance(answers, dict):
            raise IniError("--answers must be a JSON object")
        with open(args.sample, encoding="utf-8") as fh:
            text = build_ini(fh.read(), answers)
    except (OSError, ValueError) as exc:     # IniError and JSONDecodeError are ValueErrors
        print(f"ispconfig ini: {exc}", file=sys.stderr)
        return 2
    # 0600 from the start. Not printed: Semaphore keeps the task output, and
    # an operator may have put a real password in the answers.
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    keys = [line.split("=", 1)[0] for line in text.splitlines()[1:]]
    print(f"wrote {args.out}: {len(keys)} answers")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compare", help="compare two ISPConfig versions")
    c.add_argument("a")
    c.add_argument("b")
    c.set_defaults(func=_cmd_compare)
    i = sub.add_parser("ini", help="write the answers file for update.php")
    i.add_argument("--sample", required=True)
    i.add_argument("--out", required=True)
    i.add_argument("--answers", default="{}")
    i.set_defaults(func=_cmd_ini)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
