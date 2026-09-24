import assert from "node:assert/strict";
import test from "node:test";
import { parseAuthorityControlServiceArgs } from "./authority-control-service.js";

test("Authority Control service accepts only an explicit canonical config path", () => {
  assert.deepEqual(parseAuthorityControlServiceArgs([]), {});
  assert.deepEqual(parseAuthorityControlServiceArgs(["--config", "/Users/operator/MacOperator/broker-service.json"]), {
    configPath: "/Users/operator/MacOperator/broker-service.json"
  });
  assert.throws(() => parseAuthorityControlServiceArgs(["--config", "/Users/operator/../operator/broker-service.json"]), /canonical/u);
  assert.throws(() => parseAuthorityControlServiceArgs(["--config", "/Users/operator/broker-service.json", "--unsafe"]), /Usage/u);
});
