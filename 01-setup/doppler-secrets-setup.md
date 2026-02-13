# Doppler Secrets Setup Guide

This guide covers Doppler setup for `card-fraud-rule-engine`.

## Overview

Doppler is the only supported secrets source for this repository.
Do not create or commit `.env` files.

## Prerequisites

1. Install Doppler CLI.
2. Run `doppler login`.
3. Confirm access to project `card-fraud-rule-engine`, config `local`.

## Verify Access

```powershell
doppler secrets --project=card-fraud-rule-engine --config=local
```

## Required Runtime Secrets (Local)

| Secret | Example | Purpose |
|--------|---------|---------|
| `REDIS_URL` | `redis://localhost:6379` | Velocity state + outbox |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Decision event publishing |
| `S3_ENDPOINT_URL` | `http://localhost:9000` | MinIO endpoint |
| `S3_ACCESS_KEY_ID` | `minioadmin` | MinIO access key |
| `S3_SECRET_ACCESS_KEY` | `minioadmin` | MinIO secret key |
| `S3_BUCKET_NAME` | `fraud-gov-artifacts` | Ruleset artifacts |
| `S3_REGION` | `us-east-1` | MinIO region |

## Quick Validation

```powershell
uv run doppler-secrets-verify
uv run redis-local-verify
```

## Auth Model

Authentication and authorization are enforced at API Gateway.
Rule engine does not validate tokens in-process.
