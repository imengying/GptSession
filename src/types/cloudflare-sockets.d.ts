declare module "cloudflare:sockets" {
  export interface SocketAddress {
    hostname: string;
    port: number;
  }

  export interface SocketOptions {
    allowHalfOpen?: boolean;
    secureTransport?: "off" | "on" | "starttls";
  }

  export interface TlsOptions {
    expectedServerHostname?: string;
  }

  export interface Socket {
    readonly closed: Promise<void>;
    readonly opened: Promise<unknown>;
    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
    close(): Promise<void>;
    startTls(options?: TlsOptions): Socket;
  }

  export function connect(
    address: string | SocketAddress,
    options?: SocketOptions,
  ): Socket;
}
