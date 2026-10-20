TZ = UTC
export TZ
SHELL := /bin/bash
.DEFAULT_GOAL := test
.PHONY: test fast format format-check reuse

test:
	./scripts/build.sh

fast:
	./scripts/build.sh -DskipTests -Dspotbugs.skip=true

reuse:
	reuse --no-multiprocessing lint

format:
	./mvnw -q spotless:apply

format-check:
	./mvnw -q spotless:check
