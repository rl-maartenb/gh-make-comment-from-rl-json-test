# makefile

FILES := parse-rl-json-github.py
TEST_FILE := ~/json/NodeGoat.zip-reports/report.rl.json
TEST_FILE := ./tests/report.rl.json

all: clean prep test

clean:
	rm -f 1 2 *.1 *.2 *.log
	rm -rf tmp venv
	rm -f test.md

prep: black pylama mypy

black:
	black *.py

pylama:
	pylama *.py

mypy:
	mypy *.py

test:
	./parse-rl-json-github.py $(TEST_FILE) >test.md
