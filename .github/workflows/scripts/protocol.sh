#!/usr/bin/env bash
#
# Verifies the wire-protocol contract between the Python server and Swift app.
#
# Both sides assert against lib/fixtures/crypto_vectors.json (the lib repo,
# checked out at ./lib). If regenerating it from this server changes a byte,
# the server changed the protocol without the fixtures.
#
# Requirements: pip install -r requirements.txt
#
# Usage:
#   protocol.sh verify  Regenerate the vectors and reject any difference.
#
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

readonly FIXTURE="fixtures/crypto_vectors.json"

cmd_verify() {
    HOPPIN_SERVER_DIR="$ROOT" python lib/make_vectors.py

    if ! git -C lib diff --exit-code -- "$FIXTURE"; then
        echo "::error::lib/$FIXTURE no longer matches this server. Regenerate it in the lib repo (make_vectors.py), tag it, and update both sides."
        return 1
    fi
}

dispatch "$@"
