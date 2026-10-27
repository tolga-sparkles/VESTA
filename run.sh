#!/bin/sh
set -eu
cd "$(dirname "$0")"

if [ ! -d web/node_modules ] || [ ! -f web/dist/index.html ]; then
    echo "Frontend derlenmemiş; web/ klasöründe kurulum ve derleme yapılıyor..."
    npm --prefix web install --no-audit --no-fund
    npm --prefix web run build
fi

exec .venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
