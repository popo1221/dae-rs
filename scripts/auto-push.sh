#!/bin/bash
BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null)
[ -n "$BRANCH" ] && git push origin "$BRANCH" 2>&1 | grep -v "^Password" | grep -v "^Username" || true
