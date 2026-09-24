#!/usr/bin/env node
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";
import { AuthorityControlKeyManager } from "./authority-control-keyring.js";
import { AuthorityControlProxyServer } from "./authority-control-proxy.js";
import { loadBrokerServiceStartupConfig } from "./service-startup.js";
import type { ServiceSignalSource } from "./service-entrypoint.js";

export interface AuthorityControlServiceAssembly {
  readonly proxy: AuthorityControlProxyServer;
  close(): Promise<void>;
}

/**
 * Assemble the stable owner-domain operator process from the same protected
 * Broker startup document. The process is only a peer-authenticated proxy;
 * BrokerStore remains the source of truth and the Broker remains final
 * authority for every command.
 */
export async function createAuthorityControlServiceFromBrokerConfig(options: {
  configPath: string;
  now?: () => number;
}): Promise<AuthorityControlServiceAssembly> {
  const config = await loadBrokerServiceStartupConfig(options.configPath);
  const authorityKeyConfigPath = config.authorityControlKeyConfigPath;
  const authoritySocketPath = config.authorityControlSocketPath;
  const operatorSocketPath = config.authorityOperatorSocketPath;
  const serviceId = config.authorityControlServiceId;
  if (authorityKeyConfigPath === undefined || authoritySocketPath === undefined ||
      operatorSocketPath === undefined || serviceId === undefined) {
    throw new BrokerError("PRECONDITION_FAILED", "Authority Control service configuration is incomplete");
  }
  const currentUid = process.getuid?.();
  const currentGid = process.getgid?.();
  if (currentUid === undefined || currentUid !== config.expectedEdgeUid ||
      (config.expectedEdgeGid !== undefined && currentGid !== config.expectedEdgeGid)) {
    throw new BrokerError("POLICY_DENIED", "Authority Control service is running under the wrong owner identity");
  }
  const store = new BrokerStore(config.brokerDatabasePath);
  const keyManager = new AuthorityControlKeyManager(authorityKeyConfigPath, store, options.now);
  let upstream: ReturnType<AuthorityControlKeyManager["createClient"]> | undefined;
  let proxy: AuthorityControlProxyServer | undefined;
  let closed = false;
  try {
    const loaded = await keyManager.restore();
    upstream = keyManager.createClient({
      socketPath: authoritySocketPath,
      ...(options.now === undefined ? {} : { now: options.now })
    });
    proxy = new AuthorityControlProxyServer({
      socketPath: operatorSocketPath,
      peerPolicy: {
        expectedUid: config.expectedEdgeUid,
        ...(config.expectedEdgeGid === undefined ? {} : { expectedGid: config.expectedEdgeGid })
      },
      upstream,
      authenticationKey: loaded.key.key,
      ...(options.now === undefined ? {} : { now: options.now })
    });
    return {
      proxy,
      async close(): Promise<void> {
        if (closed) return;
        closed = true;
        try {
          await proxy!.close();
        } finally {
          upstream?.dispose();
          keyManager.dispose();
          store.close();
        }
      }
    };
  } catch (error) {
    await proxy?.close().catch(() => undefined);
    upstream?.dispose();
    keyManager.dispose();
    store.close();
    throw error;
  }
}

export async function runAuthorityControlServiceMain(options: {
  configPath?: string;
  now?: () => number;
  signals?: ServiceSignalSource;
} = {}): Promise<void> {
  const configPath = options.configPath ?? defaultAuthorityControlServiceConfigPath();
  const assembly = await createAuthorityControlServiceFromBrokerConfig({
    configPath,
    ...(options.now === undefined ? {} : { now: options.now })
  });
  try {
    await assembly.proxy.listen();
    await waitForSignal(options.signals ?? process, () => assembly.close());
  } finally {
    await assembly.close();
  }
}

export function parseAuthorityControlServiceArgs(args: readonly string[]): { configPath?: string } {
  if (args.length === 0) return {};
  if (args.length === 2 && args[0] === "--config" && typeof args[1] === "string" && args[1].startsWith("/")) {
    const configPath = resolve(args[1]);
    if (configPath !== args[1] || args[1].includes("\0") || args[1].includes("\n")) {
      throw new BrokerError("PRECONDITION_FAILED", "Authority Control service config path must be canonical");
    }
    return { configPath };
  }
  throw new BrokerError("PRECONDITION_FAILED", "Usage: mac-operator-authority-service [--config /absolute/broker-service.json]");
}

export async function main(args = process.argv.slice(2)): Promise<void> {
  try {
    await runAuthorityControlServiceMain(parseAuthorityControlServiceArgs(args));
  } catch (error) {
    const brokerError = error instanceof BrokerError
      ? error
      : new BrokerError("PRECONDITION_FAILED", "Authority Control service startup failed");
    process.stderr.write(`${JSON.stringify({ schemaVersion: "0.1", ok: false, errorClass: brokerError.errorClass, message: brokerError.message, retryable: brokerError.retryable })}\n`);
    process.exitCode = 1;
  }
}

function waitForSignal(signals: ServiceSignalSource, close: () => Promise<void>): Promise<void> {
  return new Promise<void>((resolvePromise, rejectPromise) => {
    let settled = false;
    const handleSignal = () => {
      if (settled) return;
      settled = true;
      signals.removeListener("SIGINT", handleSignal);
      signals.removeListener("SIGTERM", handleSignal);
      void close().then(resolvePromise, rejectPromise);
    };
    signals.on("SIGINT", handleSignal);
    signals.on("SIGTERM", handleSignal);
  });
}

export function defaultAuthorityControlServiceConfigPath(moduleUrl = import.meta.url): string {
  return resolve(fileURLToPath(new URL("./broker-service.json", moduleUrl)));
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  void main();
}
