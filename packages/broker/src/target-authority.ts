import { resolve } from "node:path";
import type { NormalizedTarget, TargetKind } from "./policy.js";

const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const APP_PATTERN = /^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;
const APP_WINDOW_PATTERN = /^window:bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;
const UI_ELEMENT_PATTERN = /^element:[a-f0-9]{48}$/u;
const SERVICE_PATTERN = /^(?:system\/[A-Za-z0-9._:@+-]{1,240}|gui\/[1-9][0-9]{0,9}\/com\.mac-operator\.[A-Za-z0-9_:@+-]{1,96})$/u;
const LOG_SOURCE_PATTERN = /^system$|^process\/[A-Za-z0-9._+-]{1,120}$/u;
const DOCKER_OBJECT_PATTERN = /^[A-Za-z0-9._:\/-]{1,256}$/u;
const PACKAGE_PATTERN = /^[A-Za-z0-9._:@/+-]{1,255}$/u;
const JOB_PATTERN = /^job:[A-Za-z0-9._-]{1,240}$/u;
const PROCESS_PATTERN = /^all$|^pid:[1-9][0-9]{0,7}$/u;

/** Validate the reference grammar accepted from a policy-query caller. */
export function isPolicyQueryTargetReference(kind: TargetKind, reference: string): boolean {
  if (!isBoundedReference(reference)) return false;
  switch (kind) {
    case "host": return reference === "broker" || reference === "local" || reference === "owner-terminal";
    case "path": return isCanonicalAbsolutePath(reference) || SAFE_ID_PATTERN.test(reference);
    case "project": return isCanonicalAbsolutePath(reference);
    case "process": return PROCESS_PATTERN.test(reference);
    case "job": return JOB_PATTERN.test(reference);
    case "task_profile": return SAFE_ID_PATTERN.test(reference);
    case "app_set": return reference === "all";
    case "app": return APP_PATTERN.test(reference);
    case "app_window": return APP_WINDOW_PATTERN.test(reference);
    case "ui_element": return UI_ELEMENT_PATTERN.test(reference);
    case "service": return SERVICE_PATTERN.test(reference) && !reference.includes("..") && !reference.includes("//");
    case "log_source": return LOG_SOURCE_PATTERN.test(reference) && !reference.includes("..");
    case "docker_runtime": return reference === "local";
    case "docker_object": return DOCKER_OBJECT_PATTERN.test(reference) && !reference.includes("..");
    case "package": return PACKAGE_PATTERN.test(reference);
    case "power": return reference === "local";
  }
}

/** Validate a target reference that is allowed to enter signed Broker policy. */
export function isSignedPolicyTargetReference(target: NormalizedTarget): boolean {
  const { kind, reference } = target;
  if (!isBoundedReference(reference)) return false;
  switch (kind) {
    case "host": return reference === "broker" || reference === "local" || reference === "owner-terminal";
    case "path": return SAFE_ID_PATTERN.test(reference);
    case "project": return isCanonicalAbsolutePath(reference);
    case "process": return PROCESS_PATTERN.test(reference);
    case "job": return reference === "owned";
    case "task_profile": return SAFE_ID_PATTERN.test(reference);
    case "app_set": return reference === "all";
    case "app": return APP_PATTERN.test(reference);
    case "app_window": return APP_WINDOW_PATTERN.test(reference);
    case "ui_element": return UI_ELEMENT_PATTERN.test(reference);
    case "service": return SERVICE_PATTERN.test(reference) && !reference.includes("..") && !reference.includes("//");
    case "log_source": return LOG_SOURCE_PATTERN.test(reference) && !reference.includes("..");
    case "docker_runtime": return reference === "local";
    case "docker_object": return DOCKER_OBJECT_PATTERN.test(reference) && !reference.includes("..");
    case "package": return PACKAGE_PATTERN.test(reference);
    case "power": return reference === "local";
  }
}

export function isCanonicalAbsolutePath(reference: string): boolean {
  return reference.startsWith("/") && resolve(reference) === reference;
}

function isBoundedReference(reference: string): boolean {
  return reference.length >= 1 && reference.length <= 4_096 && !reference.includes("\0") && !/[\r\n]/u.test(reference);
}
