# goaccesslog

## Introduction

Copies nginx access log file entries into a sqlite database.
Currently only a fixed log format is supported.
Start the program to see the required log format.

The program is intended to be used on linux servers.

## How to build

- Install the required go version (see go.mod).
- Set CFG_ENBALED = 1 and install gcc (required to build sqlite).
- go build
