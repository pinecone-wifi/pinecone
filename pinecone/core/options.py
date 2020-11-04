from __future__ import annotations
from itertools import chain
from functools import total_ordering
from typing import Iterable, Any, Sequence, Optional, NoReturn, Text
from argparse import ArgumentParser

from sortedcontainers import SortedSet


class OptionsArgumentParser(ArgumentParser):
    def exit(self, status: int = ..., message: Optional[Text] = ...) -> NoReturn:
        pass

    def error(self, message: Text) -> NoReturn:
        pass


@total_ordering
class Option:
    def __init__(self, name="", value: Any = "", required=False, description="", is_list=False, opt_type=None,
                 choices: Iterable = None):
        self.name = name
        self.value: Any = value
        self.required = required
        self.description = description

        self._parser = OptionsArgumentParser()
        self._parser.add_argument("value", nargs="+" if is_list else None, type=opt_type, choices=choices)

    def parse(self, read_input: Sequence[str] = None):
        self.value = self._parser.parse_args(read_input).value

    def required_to_str(self) -> str:
        return "yes" if self.required else "no"

    def value_to_str(self) -> str:
        return " ".join(str(v) for v in self.value) if type(self.value) == list else str(self.value)

    def __lt__(self, other: Option):
        return self.name < other.name

    def __eq__(self, other: Option):
        return self.name.casefold() == other.name.casefold()

    def __hash__(self):
        return hash(self.name.casefold())

    def __str__(self):
        return f"{self.name}  {self.value_to_str()}  {self.required_to_str()}  {self.description}"


# TODO type hint SortedSet[Option]?
class OptionSet(SortedSet):
    def __str__(self):
        name_col_len = max(chain((len(opt.name) for opt in self), (4,)))
        value_col_len = max(chain((len(opt.value_to_str()) for opt in self), (15,)))

        ret = f"{'Name': <{name_col_len}}  {'Current setting': <{value_col_len}}  Required  Description\n" \
              f"{'-'*4: <{name_col_len}}  {'-'*15: <{value_col_len}}  {'-'*8}  {'-'*11}\n"

        for opt in self:
            ret += f"{opt.name: <{name_col_len}}  {opt.value_to_str(): <{value_col_len}}  {opt.required_to_str(): <8}" \
                   f"  {opt.description}\n"

        return ret[:-1]
