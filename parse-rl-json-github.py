#! /usr/bin/env python3

from typing import (
    Dict,
    List,
    Any,
)
import sys
from os import access, R_OK
from os.path import isfile
import json


class ParseRlJsonForGithubComment:

    def __init__(self, file_name: str) -> None:
        self.file_name = file_name

        self.data: Dict[str, Any] = {}

        self.info: Dict[str, Any] = {}
        self.identity: Dict[str, Any] = {}

        self.meta: Dict[str, Any] = {}
        self.asses: Dict[str, Any] = {}
        self.lines: List[str] = []

        self._parse()

    def _load(self) -> None:
        with open(self.file_name, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def _get_meta(self) -> None:
        k = "metadata"
        self.meta = self.data.get("report", {}).get(k, {})
        if len(self.meta) == 0:
            raise Exception(f"No {k} found in file: {self.file_name}")

    def _get_assess(self) -> None:
        if len(self.meta) == 0:
            self._get_meta()

        k = "assessments"
        self.assess = self.meta.get(k, {})
        if len(self.assess) == 0:
            raise Exception(f"No {k} found in file: {self.file_name}")

    def _line(self, line: str = "") -> None:
        self.lines.append(line)

    def _get_info(self) -> None:
        self.info = self.data.get("report", {}).get("info", {})

    def _get_identity(self) -> None:
        if len(self.info) == 0:
            self._get_info()
        self.identity = self.info.get("file", {}).get("identity", {})

    def _parse(self) -> None:
        if len(self.data) == 0:
            self._load()
        self._get_assess()
        self._get_identity()

        purl = self.identity.get("purl")
        name = self.identity.get("name")

        if purl:
            self._line(f"# {purl}")
        else:
            self._line(f"# {name}")
        self._line()

        indent_1 = "    -"

        for k, v in self.assess.items():
            label = v.get("label", "").capitalize()
            status = v.get("status", "")
            count = v.get("count", "")

            if k != "vulnerabilities":
                if count == 0:
                    self._line(f"- {k.capitalize()}: **{status}**; *{label}*")
                else:
                    self._line(f"- {k.capitalize()}: **{status}**; {count} *{label}*")
                continue

            self._line(f"- {k.capitalize()}: ")
            self._line(f"{indent_1} *{label}*; **{status}** {count}")
            for eva in v.get("evaluations", []):
                e_label = eva.get("label", "").capitalize()
                e_status = eva.get("status", "")
                e_count = eva.get("count", "")
                self._line(f"{indent_1} *{e_label}*: **{e_status}**, {e_count}")

        self._line()

    def out(self) -> str:
        return "\n".join(self.lines)


def xmain():
    file_name = sys.argv[1]
    if isfile(file_name) and access(file_name, R_OK):
        prjfgc = ParseRlJsonForGithubComment(file_name=file_name)
        print(prjfgc.out())


xmain()
