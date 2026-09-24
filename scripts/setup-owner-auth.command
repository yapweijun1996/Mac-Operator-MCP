#!/bin/zsh
set -eu
umask 077

REPOSITORY_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
AUTH_PARENT="$HOME/Library/Application Support/MacOperator"
AUTH_DIRECTORY="$AUTH_PARENT/auth"

if (( $# != 0 )); then print -u2 'This wrapper takes no arguments; use the auth CLI for custom paths.'; exit 1; fi
if [[ ! -f "$REPOSITORY_ROOT/packages/auth/dist/cli.js" ]]; then
  print -u2 'Run npm run build in the repository before setup.'
  exit 1
fi
if [[ -e "$AUTH_DIRECTORY" || -L "$AUTH_DIRECTORY" ]]; then
  print -u2 'An auth directory already exists. Setup will not replace it.'
  exit 1
fi
if [[ ! -e "$AUTH_PARENT" ]]; then mkdir "$AUTH_PARENT"; fi
# Validate the existing parent before asking for credentials.
node --input-type=module -e 'const {assertPrivateDirectory}=await import(process.argv[1]); assertPrivateDirectory(process.argv[2]);' \
  "file://$REPOSITORY_ROOT/packages/auth/dist/store.js" "$AUTH_PARENT"

# RFC 9207 issuer identification permits ChatGPT's stable callback.
CALLBACK_URI='https://chatgpt.com/connector_platform_oauth_redirect'
if [[ -e "$REPOSITORY_ROOT/.env" || -L "$REPOSITORY_ROOT/.env" ]]; then
  print 'Initializing from the local .env file. Credential values will not be printed.'
  exec node "$REPOSITORY_ROOT/packages/auth/dist/cli.js" init \
    --dir "$AUTH_DIRECTORY" --env-file "$REPOSITORY_ROOT/.env" \
    --issuer https://mac.yapweijun1996.com/ --port 3444 --redirect-uri "$CALLBACK_URI"
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  print -u2 'Create an owner-only .env file or run this setup in an interactive terminal.'
  exit 1
fi
read 'OWNER_USERNAME?Username [yapweijun]: '
OWNER_USERNAME="${OWNER_USERNAME:-yapweijun}"
print 'ChatGPT callback configured automatically.'
print 'Next: enter a NEW password twice (14+ characters). Input will be hidden.'
exec node "$REPOSITORY_ROOT/packages/auth/dist/cli.js" init \
  --dir "$AUTH_DIRECTORY" --username "$OWNER_USERNAME" \
  --issuer https://mac.yapweijun1996.com/ --port 3444 \
  --redirect-uri "$CALLBACK_URI"
