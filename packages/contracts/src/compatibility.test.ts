import assert from "node:assert/strict";
import test from "node:test";
import {
  CONTRACT_VERSION,
  PROTOCOL_VERSION,
  VERSION_COMPATIBILITY,
  isCompatibleVersionPair,
  isSupportedContractVersion,
  isSupportedProtocolVersion
} from "./index.js";

test("version compatibility matrix exposes explicit domain bindings", () => {
  assert.deepEqual(VERSION_COMPATIBILITY.edge_broker, {
    protocolVersions: [PROTOCOL_VERSION],
    contractVersions: [CONTRACT_VERSION]
  });
  assert.deepEqual(VERSION_COMPATIBILITY.broker_helper, VERSION_COMPATIBILITY.edge_broker);
  assert.deepEqual(VERSION_COMPATIBILITY.capability_discovery, VERSION_COMPATIBILITY.edge_broker);
  assert.deepEqual(VERSION_COMPATIBILITY.authority_control, {
    protocolVersions: [PROTOCOL_VERSION],
    contractVersions: []
  });
});

test("version compatibility rejects unknown versions and cross-domain combinations", () => {
  assert.equal(isSupportedProtocolVersion(PROTOCOL_VERSION), true);
  assert.equal(isSupportedProtocolVersion("9.9"), false);
  assert.equal(isSupportedContractVersion(CONTRACT_VERSION), true);
  assert.equal(isSupportedContractVersion("9.9"), false);
  assert.equal(isCompatibleVersionPair("edge_broker", PROTOCOL_VERSION, CONTRACT_VERSION), true);
  assert.equal(isCompatibleVersionPair("edge_broker", "9.9", CONTRACT_VERSION), false);
  assert.equal(isCompatibleVersionPair("edge_broker", PROTOCOL_VERSION, "9.9"), false);
  assert.equal(isCompatibleVersionPair("authority_control", PROTOCOL_VERSION), true);
  assert.equal(isCompatibleVersionPair("authority_control", PROTOCOL_VERSION, CONTRACT_VERSION), false);
});
