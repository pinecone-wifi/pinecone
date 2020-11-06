from __future__ import annotations

import re
from itertools import chain
from typing import Iterable, Any, Sequence, Optional, NoReturn, Text
from argparse import ArgumentParser
from types import SimpleNamespace

from sortedcontainers import SortedDict


class OptionsArgumentParser(ArgumentParser):
    def exit(self, status: int = ..., message: Optional[Text] = ...) -> NoReturn:
        pass

    def error(self, message: Text) -> NoReturn:
        pass


class Option:
    # TODO: move str_none_empty and str2bool away.
    @classmethod
    def str_none_empty(cls, string: Optional[str]) -> str:
        return "" if string is None else str(string)

    @classmethod
    def str2bool(cls, string: Optional[str]) -> bool:
        if string is None:
            return False

        return string.casefold() in {"true", "yes", "t", "y", "1"}

    def __init__(self, name="", value=None, required=False, description: Optional[str] = None, opt_type=str,
                 choices: Iterable = None, is_list=False):
        self.name = name
        self.value: Any = value
        self.required = required
        self.description = description

        self._parser = OptionsArgumentParser()
        self._parser.add_argument("value", nargs="+" if is_list else None,
                                  type=self.str2bool if opt_type == bool else opt_type, choices=choices)

    def parse(self, read_input: Sequence[str] = None):
        self.value = self._parser.parse_args(read_input).value

    def required_to_str(self) -> str:
        return "yes" if self.required else "no"

    def value_to_str(self) -> str:
        return " ".join(str_none_empty(v) for v in self.value) if type(self.value) == list else \
            str_none_empty(self.value)

    def name_to_attr(self) -> str:
        return re.sub("([a-z])([A-Z])", r"\1_\2", self.name).lower()

    def __str__(self):
        return f"{self.name}  {self.value_to_str()}  {self.required_to_str()}  {self.description}"


# TODO type hint SortedDict[str, Option]?
class OptionDict(SortedDict):
    def add(self, option: Option):
        self[option.name] = option

    def get_val(self, key: str) -> Any:
        return self[key].value

    def get_opts_namespace(self) -> Any:
        opts_namespace = SimpleNamespace()

        for opt in self.values():
            setattr(opts_namespace, opt.name_to_attr(), opt.value)

        return opts_namespace

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
