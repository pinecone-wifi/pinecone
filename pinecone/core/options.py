from __future__ import annotations
from itertools import chain
from typing import Iterable, Any, Sequence, Optional, NoReturn, Text
from argparse import ArgumentParser

from sortedcontainers import SortedDict


class OptionsArgumentParser(ArgumentParser):
    def exit(self, status: int = ..., message: Optional[Text] = ...) -> NoReturn:
        pass

    def error(self, message: Text) -> NoReturn:
        pass


class Option:
    def __init__(self, name="", value=None, required=False, description: Optional[str] = None, opt_type=None,
                 choices: Iterable = None, is_list=False):
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

    def __str__(self):
        return f"{self.name}  {self.value_to_str()}  {self.required_to_str()}  {self.description}"


# TODO type hint SortedDict[str, Option]?
class OptionDict(SortedDict):
    def add(self, option: Option):
        self[option.name] = option

    def __setitem__(self, key: str, value: Option):
        super().__setitem__(key.casefold(), value)

    def __getitem__(self, item: str) -> Option:
        return super().__getitem__(item.casefold())

    def __delitem__(self, key: str):
        super().__delitem__(key.casefold())

    def __contains__(self, item: str):
        return super().__contains__(item.casefold())

    def __str__(self):
        name_col_len = max(chain((len(opt.name) for opt in self.values()), (4,)))
        value_col_len = max(chain((len(opt.value_to_str()) for opt in self.values()), (15,)))

        ret = f"{'Name': <{name_col_len}}  {'Current setting': <{value_col_len}}  Required  Description\n" \
              f"{'-'*4: <{name_col_len}}  {'-'*15: <{value_col_len}}  {'-'*8}  {'-'*11}\n"

        for opt in self.values():
            ret += f"{opt.name: <{name_col_len}}  {opt.value_to_str(): <{value_col_len}}  {opt.required_to_str(): <8}" \
                   f"  {opt.description}\n"

        return ret[:-1]
