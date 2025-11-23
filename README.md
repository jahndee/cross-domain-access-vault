# Cross-Domain Access Vault

A Clarity smart contract for issuing and validating short-lived access tokens across multiple domains.

## Overview

This contract provides a secure token-based access control system that allows trusted applications (domains) to issue and verify short-lived authentication tokens on the Stacks blockchain.

## Features

- **Domain Registration**: Register trusted applications as domains
- **Token Issuance**: Generate short-lived access tokens (600 blocks ≈ 1 hour)
- **Token Verification**: Validate tokens against specific domains
- **Token Revocation**: Domain admins can revoke tokens early
- **Event Logging**: Track domain registration, token issuance, and revocation

## Getting Started

### Prerequisites
- Node.js 18+
- Clarinet CLI

### Installation

```bash
npm install
