#!/usr/bin/env bash

find lib/ \( -name "*.cpp" -o -name "*.c" -o -name "*.h" \) -exec uncrustify -c uncrustify.cfg --replace --no-backup {} +
