import { Broker } from "./broker.js";
import { handleBrokerSocket } from "./ipc-server.js";
import { MacOsNativePeerIpcServer, type NativePeerIpcServerOptions } from "./native-peer-ipc-server.js";

export interface NativeBrokerIpcServerOptions extends Omit<NativePeerIpcServerOptions, "onSocket"> {
  broker: Broker;
  maxRequestBytes?: number;
}

/**
 * macOS-native Broker UDS transport. Native code owns accept and peer lookup;
 * accepted descriptors are handed to Node through public Socket({ fd }) and
 * then to the bounded Broker request handler.
 */
export class MacOsNativeBrokerIpcServer {
  private readonly transport: MacOsNativePeerIpcServer;

  constructor(options: NativeBrokerIpcServerOptions) {
    const maxRequestBytes = options.maxRequestBytes ?? 1_048_576;
    if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes < 256 || maxRequestBytes > 4 * 1024 * 1024) {
      throw new Error("Native Broker IPC request limit is invalid");
    }
    const { broker, maxRequestBytes: _ignored, ...transportOptions } = options;
    this.transport = new MacOsNativePeerIpcServer({
      ...transportOptions,
      onSocket: (socket) => handleBrokerSocket(socket, broker, maxRequestBytes)
    });
  }

  listen(): Promise<void> {
    return this.transport.listen();
  }

  close(): Promise<void> {
    return this.transport.close();
  }
}
