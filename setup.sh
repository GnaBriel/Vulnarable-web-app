#!/bin/bash
# Vulnarable Web App Setup Script
# FOR EDUCATIONAL PURPOSES ONLY

set -e

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  VulnWebApp Setup                                ║"
echo "║  Intentionally Vulnerable Web App                ║"
echo "║  FOR EDUCATIONAL PURPOSES ONLY                   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "Node.js not found. Please install Node.js >= 18"
    echo "   https://nodejs.org/"
    exit 1
fi

: