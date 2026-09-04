#!/bin/bash
# -------------------------------------------------------------
# Hypher AI v2 - AWS EC2 Automated User Data Deployment Script
# -------------------------------------------------------------
set -e

apt-get update -y
apt-get install -y git curl

# Install Docker & Docker Compose Plugin
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# Clone repository
git clone https://github.com/Ajimsha1080/Hypher-AI--Agentic-Security-v2.git /opt/hypher
cd /opt/hypher

# Start all microservices (Gateway + Agent Runtime + Postgres + Redis)
docker compose up -d --build
