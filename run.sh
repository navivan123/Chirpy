#!/bin/bash

if [ "$1" == "--debug" ]; then
        rm database.json
fi
go run .
