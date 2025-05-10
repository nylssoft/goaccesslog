# goaccesslog

## Introduction

Copies nginx access log file entries into a sqlite database.
Currently only a fixed log format is supported.
Start the program to see the required log format.

The program is intended to be used on linux servers.

## How to build

- Install the required go version (see go.mod).
- Set CGO_ENBALED=1 and install gcc (required to build sqlite).
- go build
- Example setup for Windows WSL see below

## Setup on Windows using WSL

### wsl
- wsl --update
- wsl --install -d Ubuntu-24.04 --name ubuntu-dev

### ubuntu update & upgrade
- cd
- sudo apt update
- sudo apt upgrade

### install build essential
- sudo apt install build-essential

### install nginx and adjust logging configuration

Note: no other process should listen on port 80

- sudo apt install nginx
- sudo nano /etc/nginx/nginx.conf

    log_format noreferer '$remote_addr - $remote_user [$time_local] $msec "$request" $request_length $status  $body_bytes_sent $request_time "$http_user_agent"';

    access_log /var/log/nginx/access.log noreferer;
- sudo nginx -t
- sudo nginx -s reload
- curl localhost
- sudo cat /var/log/nginx/access.log

### install go
- curl https://dl.google.com/go/go1.24.3.linux-amd64.tar.gz >go.tar.gz
- gunzip go.tar.gz
- tar xf go.tar
- sudo rm -rf /usr/local/go
- sudo mv go /usr/local/
- rm go.tar
- export PATH=$PATH:/usr/local/go/bin
- go version

### download source
- git clone https://github.com/nylssoft/goaccesslog.git
- cd goaccesslog

### build & develop & run
- export CGO_ENABLED=1
- go build
- code .
- sudo ./goaccesslog -verbose

### build sqlite

Start new bash

- cd
- curl https://www.sqlite.org/2025/sqlite-autoconf-3490200.tar.gz >sqlite.tar.gz
- gunzip sqlite.tar.gz
- tar xf sqlite.tar
- rm sqlite.tar
- cd sqlite-autoconf-3490200/
- ./configure
- make

### test view access log entries
- curl localhost
- wait 1 minute
- sudo ./sqlite3 ../goaccesslog/goaccesslog.db "select * from accesslog;"
