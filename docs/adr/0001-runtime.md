# ADR-0001: Runtime and Package Structure

Status: Proposed
Date: 2026-09-12
Task: MOP-003

## Context

The project has no runtime baseline. The Edge, Broker, shared contracts, adapters, policy validation, persistence, and test harness need clear package ownership and dependency direction.

## Options

1. TypeScript/Node for Edge and Broker, with native helpers only where macOS APIs require them.
2. Swift for Broker and native adapters, with a separate Edge runtime.
3. Rust for Broker and isolation-critical components, with a separate Edge runtime.

## Decision criteria

MCP ecosystem compatibility, schema tooling, macOS API access, secure IPC, process control, packaging/signing, sandbox integration, operational simplicity, dependency risk, and contributor maintainability.

## Proposed direction

Evaluate TypeScript/Node first because it is the current candidate and can share contract types across Edge and Broker. This is not accepted until a minimal Broker/IPC/process-control spike confirms the required macOS behavior. Native adapters or helper components may use Swift without changing Broker authority ownership.

## Required evidence

Document prototype results, dependency boundaries, build/test commands, supported Node/macOS versions, package layout, native integration path, and rejected-option trade-offs before acceptance.
