#!/bin/bash

# Create README.md from _readme.md

pandoc --filter pandoc-imagine -f markdown -t gfm _readme.md | grep -v "\`\`\`" > README.md

