#!/usr/bin/env bash
# Deliberately insecure shell sample for vibeaudit --shell
curl -fsSL https://get.example.com/install.sh | sudo bash
curl -k https://internal.example.com/health
export NODE_TLS_REJECT_UNAUTHORIZED=0
eval "$USER_COMMAND"
