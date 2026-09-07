#!/usr/bin/env bash
cd "$(dirname "$0")"
export JWT_SECRET="${JWT_SECRET:-SkillBridge-Demo-Secret-2026-At-Least-32-Chars-Long}"
node backend/server.js
