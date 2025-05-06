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

    def _line(self, line: str) -> None:
        self.lines.append(line)

    def _parse(self) -> None:
        if len(self.data) == 0:
            self._load()
        self._get_assess()

        self._line(f"# {self.file_name}")

        for k, v in self.assess.items():
            label = v.get("label", "")
            status = v.get("status", "")

            if k != "vulnerabilities":
                self._line(f"- {k}: **{status}**; *{label}*")
                continue

            self._line(f"- {k}: **{status}**; *{label}*")
            for evaluation in v.get("evaluations", []):
                e_label = evaluation.get("label", "")
                e_status = evaluation.get("status", "")
                self._line(f"    - *{e_label}*: **{e_status}**")

        self._line("")

    def out(self) -> str:
        return "\n".join(self.lines)


def xmain():
    file_name = sys.argv[1]
    if isfile(file_name) and access(file_name, R_OK):
        prjfgc = ParseRlJsonForGithubComment(file_name=file_name)
        print(prjfgc.out())


xmain()
