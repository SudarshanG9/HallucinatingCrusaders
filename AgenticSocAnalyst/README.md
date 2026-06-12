# Agentic AI SOC Analyst

An autonomous AI-powered Security Operations Center analyst that collects, analyzes, and responds to security events using LLM-driven agents.

## Project Structure

```
AgenticSocAnalyst/
├── .env                        ← API keys (never commit)
├── .env.example                ← Template for others
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── setup.ps1
├── infrastructure/             ← Wazuh/Postgres certs & configs
├── scripts/                    ← Setup helpers
├── soc_analyst/                ← ALL actual code
└── tests/                      ← Unit tests
```

## Quick Start

```bash
cp .env.example .env
# Fill in your API keys in .env

docker-compose up --build
```

## Requirements

See `requirements.txt` for Python dependencies.