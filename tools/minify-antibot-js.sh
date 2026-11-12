#!/bin/sh
# Regenerates the minified anti-bot scripts served by ProxyAuth from their
# readable sources in src/network/antibot_js/. Run after editing them:
#   sh tools/minify-antibot-js.sh
# Needs Node.js (npx downloads terser on first use). No comment survives.
set -e
cd "$(dirname "$0")/../src/network/antibot_js"
for f in challenge worker; do
  npx --yes terser@5 "$f.js" --compress passes=2 --mangle --comments false \
    --output "$f.min.js"
  echo "$f.min.js: $(wc -c < "$f.min.js") bytes (source: $(wc -c < "$f.js"))"
done
