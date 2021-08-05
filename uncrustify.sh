#!/usr/bin/env bash

find lib/ \( -name "*.cpp" -o -name "*.hpp" \) -exec uncrustify -c uncrustify.cfg --replace --no-backup {} +
