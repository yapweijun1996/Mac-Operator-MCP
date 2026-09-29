import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { resolve, join } from 'node:path';

const supported = process.platform === 'darwin';
test('native GUI transport cancels a busy application when the launcher disconnects', { skip: !supported }, async () => {
  const directory = await mkdtemp('/tmp/mop-test-');
  let server;
  let child;
  try {
    const source = join(directory, 'fixture.m');
    await writeFile(source, `#import "${resolve('packages/broker/native/gui_transport.h')}"\nint main(int argc, char **argv) { @autoreleasepool { if(argc != 2) return 1; if(receiveGuiRequest([NSString stringWithUTF8String:argv[1]]) == nil) return 74; puts("ready"); fflush(stdout); sleep(30); return 0; } }`);
    const executable = join(directory, 'fixture');
    execFileSync('clang', ['-fobjc-arc', '-fblocks', '-framework', 'Foundation', source, '-o', executable]);
    server = createServer();
    const path = join(directory, 'socket');
    server.listen(path);
    await once(server, 'listening');
    const connection = once(server, 'connection');
    child = spawn(executable, [path], { stdio: ['ignore', 'ignore', 'pipe'] });
    const exited = once(child, 'exit');
    const [peer] = await connection;
    const body = Buffer.from(JSON.stringify({args: [], stdin: ''}));
    const header = Buffer.alloc(4); header.writeUInt32BE(body.length);
    peer.write(Buffer.concat([header, body]));
    const [ready] = await once(peer, 'data');
    assert.equal(ready.toString(), 'ready\n');
    peer.destroy();
    const [code] = await exited;
    assert.equal(code, 75);
  } finally {
    child?.kill('SIGKILL');
    server?.close();
    await rm(directory, {recursive: true, force: true});
  }
});
