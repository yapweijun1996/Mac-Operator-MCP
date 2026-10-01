import test from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve, join } from 'node:path';

const environment = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C' };
const processOptions = (cwd) => ({ cwd, env: environment, shell: false, timeout: 30000, maxBuffer: 1024 * 1024 });

test('Dock overlay exception requires system hit ownership and preserves other overlays', {skip: process.platform !== 'darwin'}, async () => {
  const directory = await mkdtemp('/tmp/mop-hit-test-');
  try {
    const source = join(directory, 'fixture.m');
    await writeFile(source, `
#define main guiAdapterMain
#import "${resolve('packages/broker/native/gui_vision.m')}"
#undef main
#import <assert.h>
int main(void) { @autoreleasepool {
  assert(isPassThroughDockOverlay(@"com.apple.dock", 20, 100, 100));
  assert(!isPassThroughDockOverlay(@"com.apple.dock", 20, 200, 100));
  assert(!isPassThroughDockOverlay(@"com.apple.dock", 20, -1, 100));
  assert(!isPassThroughDockOverlay(@"com.apple.dock", 0, 100, 100));
  assert(!isPassThroughDockOverlay(@"com.apple.systemuiserver", 20, 100, 100));
  assert(!isPassThroughDockOverlay(nil, 20, 100, 100));
  assert(!isPassThroughDockOverlay(@"com.apple.dock", 20, 0, 0));
  assert(isExcludedScreenOverlay(@"com.apple.dock", 20));
  assert(!isExcludedScreenOverlay(@"com.apple.dock", 0));
  assert(!isExcludedScreenOverlay(@"com.apple.SecurityAgent", 20));
  assert(!isExcludedScreenOverlay(nil, 20));
  CGRect browser = CGRectMake(0, 0, 1200, 900);
  CGRect covered = CGRectMake(100, 100, 300, 200);
  CGRect outside = CGRectMake(1100, 100, 300, 200);
  assert(screenWindowBlockReason(NO, 0, browser, covered, YES) == nil);
  assert([screenWindowBlockReason(NO, 0, browser, outside, NO) isEqualToString:@"screen_other_window_visible"]);
  assert([screenWindowBlockReason(YES, 0, browser, covered, NO) isEqualToString:@"screen_window_occluded"]);
  assert([screenWindowBlockReason(YES, 20, browser, covered, YES) isEqualToString:@"sensitive_window_visible"]);
  assert(sensitiveTitle(@"Password"));
  assert(!sensitiveTitle(@"Text input"));
} return 0; }
`);
    const executable = join(directory, 'fixture');
    execFileSync('/usr/bin/clang', ['-fobjc-arc', '-fblocks', '-Wno-deprecated-declarations', '-framework', 'AppKit', '-framework', 'ApplicationServices', '-framework', 'ScreenCaptureKit', source, '-o', executable], processOptions(directory));
    execFileSync(executable, [], { ...processOptions(directory), timeout: 10000 });
  } finally { await rm(directory, {recursive:true, force:true}); }
});
