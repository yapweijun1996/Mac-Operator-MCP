import assert from "node:assert/strict";
import test from "node:test";
import {
  executeMacOsLaunchAgentPlans,
  executeMacOsLaunchAgentDeployment,
  executeMacOsLaunchAgentDeploymentWithAuthority,
  MacOsLaunchAgentDeploymentError,
  type MacOsLaunchAgentComponentAction
} from "./macos-install-coordinator.js";

function plan(component: "mac-operator-edge" | "mac-operator-broker", operation: "install" | "uninstall", signaturePolicy: "developer-id" | "development-ad-hoc") {
  return {
    component,
    operation,
    domain: "gui/501",
    userHome: "/Users/operator",
    installRoot: "/Users/operator/Library/Application Support/MacOperator",
    signaturePolicy,
    signature: signaturePolicy === "developer-id"
      ? { identifier: component, teamIdentifier: "ABCDE12345", cdHash: "a".repeat(40) }
      : { identifier: component },
    notarizationAssess: signaturePolicy === "developer-id" ? {} : undefined
  } as never;
}

function execution() {
  return {
    readExistingService: async () => ({ present: false, sourceRevision: null }),
    readback: async () => null,
    ownerUid: 501
  } as never;
}

function uninstallExecution() {
  return {
    readExistingService: async () => ({ present: false, sourceRevision: null }),
    readback: async () => null,
    ownerUid: 501,
    edgeId: "edge-1",
    disableGlobal: async () => undefined,
    revokeEdge: async () => undefined,
    authorityReadback: async () => ({ globalDisabled: true, edgeRevoked: true })
  } as never;
}

function action<T>(
  component: "authority" | "edge" | "broker",
  operation: "install" | "upgrade" | "rollback" | "uninstall",
  events: string[],
  result: T,
  recoverResult: unknown = undefined
): MacOsLaunchAgentComponentAction<T> {
  return {
    component,
    operation,
    execute: async () => {
      events.push(`${component}:execute`);
      if (result instanceof Error) throw result;
      return result;
    },
    recover: async () => {
      events.push(`${component}:recover`);
      if (recoverResult instanceof Error) throw recoverResult;
      return recoverResult;
    }
  };
}

test("LaunchAgent deployment installs Edge before Broker and returns both readbacks", async () => {
  const events: string[] = [];
  const result = await executeMacOsLaunchAgentDeployment({
    operation: "install",
    edge: action("edge", "install", events, { component: "edge" }),
    broker: action("broker", "install", events, { component: "broker" })
  });
  assert.deepEqual(events, ["edge:execute", "broker:execute"]);
  assert.deepEqual(result.order, ["edge", "broker"]);
  assert.deepEqual(result.edge, { component: "edge" });
  assert.deepEqual(result.broker, { component: "broker" });
});

test("Broker failure recovers the completed Edge action and reports recovered state", async () => {
  const events: string[] = [];
  await assert.rejects(
    executeMacOsLaunchAgentDeployment({
      operation: "upgrade",
      edge: action("edge", "upgrade", events, { component: "edge" }),
      broker: action("broker", "upgrade", events, new Error("broker failed"))
    }),
    (error: unknown) => {
      assert.ok(error instanceof MacOsLaunchAgentDeploymentError);
      assert.equal(error.code, "COMMAND_FAILED");
      assert.deepEqual(error.details, {
        operation: "upgrade",
        failedComponent: "broker",
        completedComponents: ["edge"],
        recoveryAttempted: true,
        recoveryCompleted: true,
        recoveryState: "recovered"
      });
      return true;
    }
  );
  assert.deepEqual(events, ["edge:execute", "broker:execute", "edge:recover"]);
});

test("Recovery failure is explicit and does not claim deployment success", async () => {
  const events: string[] = [];
  await assert.rejects(
    executeMacOsLaunchAgentDeployment({
      operation: "rollback",
      edge: action("edge", "rollback", events, { component: "edge" }, new Error("edge recovery failed")),
      broker: action("broker", "rollback", events, new Error("broker failed"))
    }),
    (error: unknown) => {
      assert.ok(error instanceof MacOsLaunchAgentDeploymentError);
      assert.equal(error.code, "RECOVERY_FAILED");
      assert.equal(error.details.recoveryState, "recovery-required");
      assert.equal(error.details.recoveryCompleted, false);
      return true;
    }
  );
  assert.deepEqual(events, ["edge:execute", "broker:execute", "edge:recover"]);
});

test("Uninstall reverses the service order and recovers Broker when Edge removal fails", async () => {
  const events: string[] = [];
  await assert.rejects(
    executeMacOsLaunchAgentDeployment({
      operation: "uninstall",
      edge: action("edge", "uninstall", events, new Error("edge removal failed")),
      broker: action("broker", "uninstall", events, { component: "broker" })
    }),
    (error: unknown) => error instanceof MacOsLaunchAgentDeploymentError &&
      error.details.recoveryState === "recovered" &&
      error.details.completedComponents[0] === "broker"
  );
  assert.deepEqual(events, ["broker:execute", "edge:execute", "broker:recover"]);
});

test("Operation mismatch and missing recovery are rejected before host mutation", async () => {
  const events: string[] = [];
  const invalid = {
    operation: "install" as const,
    edge: action("edge", "upgrade", events, { component: "edge" }),
    broker: action("broker", "install", events, { component: "broker" })
  };
  await assert.rejects(executeMacOsLaunchAgentDeployment(invalid), MacOsLaunchAgentDeploymentError);
  assert.deepEqual(events, []);
  await assert.rejects(
    executeMacOsLaunchAgentDeployment({
      operation: "install",
      edge: { component: "edge", operation: "install", execute: async () => ({}), recover: undefined as never },
      broker: action("broker", "install", events, {})
    }),
    MacOsLaunchAgentDeploymentError
  );
  assert.deepEqual(events, []);
});

test("Production plan assembly rejects ad-hoc primary or inverse artifacts before execution", async () => {
  const events: string[] = [];
  const adHocEdge = plan("mac-operator-edge", "install", "development-ad-hoc");
  const adHocEdgeRecovery = plan("mac-operator-edge", "uninstall", "development-ad-hoc");
  const broker = plan("mac-operator-broker", "install", "developer-id");
  const brokerRecovery = plan("mac-operator-broker", "uninstall", "developer-id");
  await assert.rejects(
    executeMacOsLaunchAgentPlans({
      mode: "production",
      operation: "install",
      edge: { plan: adHocEdge, execution: execution(), recovery: { plan: adHocEdgeRecovery, execution: execution() } },
      broker: { plan: broker, execution: { install: execution() }, recovery: { plan: brokerRecovery, execution: { uninstall: uninstallExecution() } } }
    }),
    (error: unknown) => error instanceof MacOsLaunchAgentDeploymentError ||
      (error instanceof Error && /Developer ID/u.test(error.message))
  );
  assert.deepEqual(events, []);
});

test("Broker uninstall assembly requires the authority-gated execution path before mutation", async () => {
  const edge = plan("mac-operator-edge", "uninstall", "development-ad-hoc");
  const edgeRecovery = plan("mac-operator-edge", "install", "development-ad-hoc");
  const broker = plan("mac-operator-broker", "uninstall", "development-ad-hoc");
  const brokerRecovery = plan("mac-operator-broker", "install", "development-ad-hoc");
  await assert.rejects(
    executeMacOsLaunchAgentPlans({
      mode: "development-probe",
      operation: "uninstall",
      edge: { plan: edge, execution: execution(), recovery: { plan: edgeRecovery, execution: execution() } },
      broker: { plan: broker, execution: { install: execution() }, recovery: { plan: brokerRecovery, execution: { install: execution() } } }
    }),
    /malformed/u
  );
});

test("three-component deployment starts Authority, Edge, and Broker, then recovers in reverse order", async () => {
  const events: string[] = [];
  const result = await executeMacOsLaunchAgentDeploymentWithAuthority({
    operation: "install",
    authority: action("authority", "install", events, { component: "authority" }),
    broker: action("broker", "install", events, { component: "broker" }),
    edge: action("edge", "install", events, { component: "edge" })
  });
  assert.deepEqual(result.order, ["authority", "edge", "broker"]);
  assert.deepEqual(events, ["authority:execute", "edge:execute", "broker:execute"]);

  events.length = 0;
  await assert.rejects(
    executeMacOsLaunchAgentDeploymentWithAuthority({
      operation: "install",
      authority: action("authority", "install", events, { component: "authority" }),
      broker: action("broker", "install", events, new Error("broker failed")),
      edge: action("edge", "install", events, { component: "edge" })
    }),
    (error: unknown) => error instanceof MacOsLaunchAgentDeploymentError &&
      error.details.recoveryState === "recovered" &&
      error.details.completedComponents.join(",") === "authority,edge"
  );
  assert.deepEqual(events, [
    "authority:execute", "edge:execute", "broker:execute",
    "edge:recover", "authority:recover"
  ]);
});
