import assert from "node:assert/strict";
import { before, after, test } from "node:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

let directory, executable;
const options = { env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }, timeout: 30000, maxBuffer: 65536 };
before(async () => {
  if (process.platform !== "darwin") return;
  directory = await mkdtemp("/tmp/mop-window-tests-");
  options.env.TMPDIR = directory;
  executable = join(directory, "window-fixture");
  const source = join(directory, "fixture.m");
  await writeFile(source, `
#define main guiAdapterMain
#import "${resolve("packages/broker/native/gui_vision.m")}"
#undef main
#import <assert.h>
static NSDictionary *windowInfo(int number, int pid, NSString *title, CGRect bounds, BOOL visible) {
  return @{(id)kCGWindowNumber:@(number), (id)kCGWindowOwnerPID:@(pid), (id)kCGWindowName:title,
    (id)kCGWindowBounds:(__bridge_transfer NSDictionary *)CGRectCreateDictionaryRepresentation(bounds),
    (id)kCGWindowLayer:@0, (id)kCGWindowAlpha:@1, (id)kCGWindowIsOnscreen:@(visible)};
}
int main(int argc, const char *argv[]) { @autoreleasepool {
  assert(argc == 2); NSString *scenario = [NSString stringWithUTF8String:argv[1]];
  CGRect bounds = CGRectMake(83,30,1200,916); NSUInteger position = NSNotFound; NSString *reason = nil;
  NSDictionary *active = windowInfo(46,485,@"Page",bounds,YES);
  if ([scenario isEqualToString:@"title"]) {
    NSDictionary *selected = correlateWindow(@[active],485,bounds,&position,&reason);
    assert(selected == active && position == 0); // AX title may include Chrome's profile/group suffix.
    NSDictionary *renamed = windowInfo(46,485,@"Renamed page",bounds,YES);
    assert([correlateWindow(@[renamed],485,bounds,&position,&reason)[(id)kCGWindowNumber] intValue] == 46);
  } else if ([scenario isEqualToString:@"multiple"]) {
    NSDictionary *other = windowInfo(47,485,@"Page",CGRectMake(120,80,1200,916),YES);
    NSDictionary *helper = windowInfo(48,999,@"Page",bounds,YES);
    assert(correlateWindow(@[helper,other,active],485,bounds,&position,&reason) == active && position == 2);
    assert(correlateWindow(@[active,other],485,CGRectMake(120,80,1200,916),&position,&reason) == other);
  } else if ([scenario isEqualToString:@"ambiguous"]) {
    assert(correlateWindow(@[active,windowInfo(47,485,@"Other",bounds,YES)],485,bounds,&position,&reason) == nil);
    assert([reason isEqualToString:@"window_ambiguous"]);
  } else if ([scenario isEqualToString:@"unavailable"]) {
    assert(correlateWindow(@[],485,bounds,&position,&reason) == nil);
    assert([reason isEqualToString:@"window_correlation_failed"]);
    assert(correlateWindow(@[windowInfo(46,485,@"Hidden",bounds,NO)],485,bounds,&position,&reason) == nil);
    assert(correlateWindow(@[active],486,bounds,&position,&reason) == nil);
    assert(correlateWindow(@[active],485,CGRectMake(0,0,1200,916),&position,&reason) == nil);
  } else if ([scenario isEqualToString:@"nodes"]) {
    return emit(@{@"plain":guiNode(0,@"AXTextField",@"Text input",YES,YES,NO,NO),
      @"secure":guiNode(1,@"AXSecureTextField",@"Never expose",YES,NO,YES,YES)});
  } else if ([scenario isEqualToString:@"navigation"]) {
    assert(browserNavigationAncestors(@[@"AXTextField",@"AXGroup",@"AXToolbar",@"AXWindow"]));
    assert(!browserNavigationAncestors(@[@"AXTextField",@"AXWebArea",@"AXToolbar",@"AXWindow"]));
    assert(!browserNavigationAncestors(@[@"AXTextField",@"AXToolbar",@"AXWebArea",@"AXWindow"]));
    assert(!browserNavigationAncestors(@[@"AXTextField",@"AXGroup",@"AXWindow"]));
  } else if ([scenario isEqualToString:@"navigation-readback"]) {
    assert(boundedNavigationInput(@"https://example.com/path",@[],YES));
    assert(!boundedNavigationInput(@"https://example.com/path",@[@"TAB",@"ENTER"],NO));
    assert(!boundedNavigationInput(@"http://example.com/path",@[],YES));
    assert(!boundedNavigationInput(@"https://user:secret@example.com/path",@[],YES));
    assert(navigationDispatchAllowed(YES,YES,@"https://example.com/",@[],YES));
    assert(!navigationDispatchAllowed(YES,NO,@"https://example.com/",@[],YES));
    assert(!navigationDispatchAllowed(YES,YES,@"https://example.com/",@[@"TAB",@"ENTER"],NO));
    assert(navigationAddressMatches(@"https://example.com/path",@"example.com/path"));
    assert(navigationAddressMatches(@"https://example.com/",@"https://example.com"));
    assert(!navigationAddressMatches(@"https://example.com/path",@"https://other.com/path"));
    assert(!navigationAddressMatches(@"https://example.com/path",@"https://example.com/redirect"));
    assert(!navigationAddressMatches(@"https://example.com/path",@"http://example.com/path"));
  } else return 2;
} return 0; }
`);
  execFileSync("/usr/bin/clang", ["-fobjc-arc", "-fblocks", "-Wno-deprecated-declarations", "-framework", "AppKit", "-framework", "ApplicationServices", "-framework", "ScreenCaptureKit", source, "-o", executable], options);
});
after(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });
for (const [scenario, name] of [
  ["title", "native AX/CG correlation survives different and changing browser titles"],
  ["multiple", "native correlation selects exact PID/geometry among multiple windows and helper processes"],
  ["ambiguous", "native correlation fails closed for indistinguishable windows"],
  ["unavailable", "native correlation rejects stale, absent, hidden and wrong-process windows"],
  ["navigation", "native toolbar authority excludes web fields and webpage toolbar impersonation"],
  ["navigation-readback", "native navigation verifies the exact toolbar address despite normal focus movement"]
]) test(name, { skip: process.platform !== "darwin" }, () => execFileSync(executable, [scenario], options));
test("native node serialization returns strict booleans and masks secure labels", { skip: process.platform !== "darwin" }, () => {
  const result = JSON.parse(execFileSync(executable, ["nodes"], options));
  for (const node of [result.plain, result.secure]) for (const name of ["enabled", "focused", "secure", "browser_navigation"]) assert.equal(typeof node[name], "boolean");
  assert.equal(result.plain.focused, true);
  assert.equal(result.secure.label, "");
  assert.equal(result.secure.browser_navigation, false);
});
