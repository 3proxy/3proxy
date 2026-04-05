#!/bin/sh
# Post-install script for 3proxy
# Creates proxy user and group if they don't exist

set -e

# Check if user already exists
if id proxy >/dev/null 2>&1; then
    echo "User 'proxy' already exists"
    exit 0
fi

echo "Creating proxy user and group..."

# Determine which commands are available
if command -v groupadd >/dev/null 2>&1; then
    # Linux (shadow-utils)
    groupadd -r proxy 2>/dev/null || true
    useradd -r -g proxy -d /var/run/3proxy -s /usr/sbin/nologin proxy 2>/dev/null || true
elif command -v addgroup >/dev/null 2>&1; then
    # Alpine Linux / BusyBox
    addgroup -S proxy 2>/dev/null || true
    adduser -S -D -H -G proxy -s /sbin/nologin proxy 2>/dev/null || true
elif command -v pw >/dev/null 2>&1; then
    # FreeBSD
    pw groupadd proxy 2>/dev/null || true
    pw useradd proxy -g proxy -d /var/run/3proxy -s /usr/sbin/nologin 2>/dev/null || true
elif command -v dscl >/dev/null 2>&1; then
    # macOS
    dscl . create /Groups/proxy 2>/dev/null || true
    dscl . create /Users/proxy 2>/dev/null || true
    dscl . create /Users/proxy UserShell /usr/bin/false 2>/dev/null || true
    dscl . create /Users/proxy NFSHomeDirectory /var/run/3proxy 2>/dev/null || true
else
    echo "Warning: Could not create proxy user - no suitable user management tool found"
    exit 0
fi

if id proxy >/dev/null 2>&1; then
    echo "User 'proxy' created successfully"
else
    echo "Warning: Failed to create user 'proxy'"
fi

exit 0
