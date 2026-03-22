#!/bin/bash
# Generate a list of all public repos across Red Hat GitHub orgs
# Requires: gh CLI authenticated with a GitHub token
# Output: one owner/repo per line, suitable for fluxgate batch --list

set -euo pipefail

ORGS=(
    RedHatOfficial
    redhat-developer
    openshift
    ansible
    containers
    cri-o
    keycloak
    quarkusio
    patternfly
    konveyor
    open-cluster-management-io
    operator-framework
    redhat-appstudio
    konflux-ci
    red-hat-storage
    osbuild
    ostreedev
    coreos
)

OUTFILE="${1:-redhat-repos.txt}"
TMPFILE=$(mktemp)

echo "Fetching repos from ${#ORGS[@]} Red Hat orgs..."

total=0
for org in "${ORGS[@]}"; do
    count=$(gh repo list "$org" \
        --limit 1000 \
        --visibility public \
        --no-archived \
        --json nameWithOwner \
        --jq '.[].nameWithOwner' 2>/dev/null | tee -a "$TMPFILE" | wc -l || echo 0)
    count=$(echo "$count" | tr -d ' ')
    total=$((total + count))
    echo "  $org: $count repos"
done

# Sort and deduplicate
sort -u "$TMPFILE" > "$OUTFILE"
rm "$TMPFILE"

final=$(wc -l < "$OUTFILE" | tr -d ' ')
echo ""
echo "Total: $final unique repos written to $OUTFILE"
