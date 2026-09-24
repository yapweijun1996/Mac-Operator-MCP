import {
  executeMacOsEdgeInstallPlan,
  executeMacOsAuthorityInstallPlan,
  executeMacOsInstallPlan,
  MacOsInstallPlanError,
  type MacOsEdgeInstallExecutionOptions,
  type MacOsEdgeInstallExecutionResult,
  type MacOsEdgeInstallPlan,
  type MacOsAuthorityInstallExecutionOptions,
  type MacOsAuthorityInstallExecutionResult,
  type MacOsAuthorityInstallPlan,
  type MacOsInstallExecutionOptions,
  type MacOsInstallExecutionResult,
  type MacOsInstallOperation,
  type MacOsInstallPlan
} from "./macos-install-plan.js";
import { executeMacOsUninstallPlan, type MacOsUninstallExecutionOptions } from "./macos-uninstall-plan.js";

export type MacOsDeploymentComponent = "authority" | "edge" | "broker";
export type MacOsDeploymentRecoveryState = "not-started" | "recovered" | "recovery-required";
export type MacOsLaunchAgentControllerMode = "production" | "development-probe";
type MacOsLaunchAgentPlan = MacOsInstallPlan | MacOsEdgeInstallPlan | MacOsAuthorityInstallPlan;

export interface MacOsLaunchAgentComponentAction<TResult> {
  component: MacOsDeploymentComponent;
  operation: MacOsInstallOperation;
  execute: () => Promise<TResult>;
  /**
   * Host-owned inverse action for the already-completed component. It must
   * carry its own exact precondition, confirmation, and final readback.
   */
  recover: () => Promise<unknown>;
}

export interface MacOsLaunchAgentDeploymentOptions<TEdge, TBroker> {
  operation: MacOsInstallOperation;
  edge: MacOsLaunchAgentComponentAction<TEdge>;
  broker: MacOsLaunchAgentComponentAction<TBroker>;
}

export interface MacOsLaunchAgentDeploymentResult<TEdge, TBroker> {
  operation: MacOsInstallOperation;
  order: readonly [MacOsDeploymentComponent, MacOsDeploymentComponent];
  edge: TEdge;
  broker: TBroker;
}

export interface MacOsEdgeLaunchAgentActionSpec {
  plan: MacOsEdgeInstallPlan;
  execution: Omit<MacOsEdgeInstallExecutionOptions, "confirmOperation">;
  recovery: {
    plan: MacOsEdgeInstallPlan;
    execution: Omit<MacOsEdgeInstallExecutionOptions, "confirmOperation">;
  };
}

export interface MacOsBrokerLaunchAgentExecution {
  /** Used for install, upgrade, and rollback. */
  install?: Omit<MacOsInstallExecutionOptions, "confirmOperation">;
  /** Required for uninstall; this is the authority-gated Broker path. */
  uninstall?: Omit<MacOsUninstallExecutionOptions, "confirmOperation">;
}

export interface MacOsBrokerLaunchAgentActionSpec {
  plan: MacOsInstallPlan;
  execution: MacOsBrokerLaunchAgentExecution;
  recovery: {
    plan: MacOsInstallPlan;
    execution: MacOsBrokerLaunchAgentExecution;
  };
}

export interface MacOsLaunchAgentPlanDeploymentOptions {
  mode: MacOsLaunchAgentControllerMode;
  operation: MacOsInstallOperation;
  edge: MacOsEdgeLaunchAgentActionSpec;
  broker: MacOsBrokerLaunchAgentActionSpec;
}

export interface MacOsAuthorityLaunchAgentActionSpec {
  plan: MacOsAuthorityInstallPlan;
  execution: Omit<MacOsAuthorityInstallExecutionOptions, "confirmOperation">;
  recovery: {
    plan: MacOsAuthorityInstallPlan;
    execution: Omit<MacOsAuthorityInstallExecutionOptions, "confirmOperation">;
  };
}

export interface MacOsLaunchAgentAuthorityPlanDeploymentOptions {
  mode: MacOsLaunchAgentControllerMode;
  operation: MacOsInstallOperation;
  authority: MacOsAuthorityLaunchAgentActionSpec;
  broker: MacOsBrokerLaunchAgentActionSpec;
  edge: MacOsEdgeLaunchAgentActionSpec;
}

export interface MacOsLaunchAgentAuthorityDeploymentResult<TAuthority, TBroker, TEdge> {
  operation: MacOsInstallOperation;
  order: readonly [MacOsDeploymentComponent, MacOsDeploymentComponent, MacOsDeploymentComponent];
  authority: TAuthority;
  broker: TBroker;
  edge: TEdge;
}

export interface MacOsLaunchAgentDeploymentFailureDetails {
  operation: MacOsInstallOperation;
  failedComponent: MacOsDeploymentComponent;
  completedComponents: readonly MacOsDeploymentComponent[];
  recoveryAttempted: boolean;
  recoveryCompleted: boolean;
  recoveryState: MacOsDeploymentRecoveryState;
}

/**
 * Host-only error for the two-component LaunchAgent transaction. The error
 * deliberately contains no command output or path-derived detail.
 */
export class MacOsLaunchAgentDeploymentError extends MacOsInstallPlanError {
  readonly details: MacOsLaunchAgentDeploymentFailureDetails;
  readonly cause: unknown;

  constructor(
    code: "COMMAND_FAILED" | "RECOVERY_FAILED",
    message: string,
    details: MacOsLaunchAgentDeploymentFailureDetails,
    cause: unknown = undefined
  ) {
    super(code, message);
    this.name = "MacOsLaunchAgentDeploymentError";
    this.details = details;
    this.cause = cause;
  }
}

/**
 * Executes a plan set through the existing component executors. Production
 * mode requires Developer ID and notarization plans for both primary and
 * inverse actions; development mode is explicit and remains capability-free
 * when the underlying plan builder is given an ad-hoc signature.
 */
export async function executeMacOsLaunchAgentPlans(
  options: MacOsLaunchAgentPlanDeploymentOptions
): Promise<MacOsLaunchAgentDeploymentResult<MacOsEdgeInstallExecutionResult, MacOsInstallExecutionResult>> {
  validatePlanDeployment(options);
  assertReleaseMode(options.mode, [
    options.edge.plan,
    options.edge.recovery.plan,
    options.broker.plan,
    options.broker.recovery.plan
  ]);
  return executeMacOsLaunchAgentDeployment({
    operation: options.operation,
    edge: {
      component: "edge",
      operation: options.edge.plan.operation,
      execute: () => executeMacOsEdgeInstallPlan(options.edge.plan, {
        ...options.edge.execution,
        confirmOperation: options.edge.plan.operation
      }),
      recover: () => executeMacOsEdgeInstallPlan(options.edge.recovery.plan, {
        ...options.edge.recovery.execution,
        confirmOperation: options.edge.recovery.plan.operation
      })
    },
    broker: {
      component: "broker",
      operation: options.broker.plan.operation,
      execute: () => executeBrokerPlan(options.broker.plan, options.broker.execution),
      recover: () => executeBrokerPlan(options.broker.recovery.plan, options.broker.recovery.execution)
    }
  });
}

/**
 * Executes the complete three-component owner-domain transaction. Authority
 * starts first, Edge starts second, and Broker starts last because Broker
 * binds both stable peer identities during startup. Uninstall reverses that
 * dependency order. Every completed component is
 * recovered in reverse order when a later component fails.
 */
export async function executeMacOsLaunchAgentPlansWithAuthority(
  options: MacOsLaunchAgentAuthorityPlanDeploymentOptions
): Promise<MacOsLaunchAgentAuthorityDeploymentResult<
  MacOsAuthorityInstallExecutionResult,
  MacOsInstallExecutionResult,
  MacOsEdgeInstallExecutionResult
>> {
  validateAuthorityPlanDeployment(options);
  assertReleaseMode(options.mode, [
    options.authority.plan,
    options.authority.recovery.plan,
    options.broker.plan,
    options.broker.recovery.plan,
    options.edge.plan,
    options.edge.recovery.plan
  ]);
  return executeMacOsLaunchAgentDeploymentWithAuthority({
    operation: options.operation,
    authority: {
      component: "authority",
      operation: options.authority.plan.operation,
      execute: () => executeMacOsAuthorityInstallPlan(options.authority.plan, {
        ...options.authority.execution,
        confirmOperation: options.authority.plan.operation
      }),
      recover: () => executeMacOsAuthorityInstallPlan(options.authority.recovery.plan, {
        ...options.authority.recovery.execution,
        confirmOperation: options.authority.recovery.plan.operation
      })
    },
    broker: {
      component: "broker",
      operation: options.broker.plan.operation,
      execute: () => executeBrokerPlan(options.broker.plan, options.broker.execution),
      recover: () => executeBrokerPlan(options.broker.recovery.plan, options.broker.recovery.execution)
    },
    edge: {
      component: "edge",
      operation: options.edge.plan.operation,
      execute: () => executeMacOsEdgeInstallPlan(options.edge.plan, {
        ...options.edge.execution,
        confirmOperation: options.edge.plan.operation
      }),
      recover: () => executeMacOsEdgeInstallPlan(options.edge.recovery.plan, {
        ...options.edge.recovery.execution,
        confirmOperation: options.edge.recovery.plan.operation
      })
    }
  });
}

export async function executeMacOsLaunchAgentDeploymentWithAuthority<TAuthority, TBroker, TEdge>(
  options: {
    operation: MacOsInstallOperation;
    authority: MacOsLaunchAgentComponentAction<TAuthority>;
    broker: MacOsLaunchAgentComponentAction<TBroker>;
    edge: MacOsLaunchAgentComponentAction<TEdge>;
  }
): Promise<MacOsLaunchAgentAuthorityDeploymentResult<TAuthority, TBroker, TEdge>> {
  validateAuthorityDeploymentOptions(options);
  const uninstall = options.operation === "uninstall";
  const ordered = uninstall
    ? [options.broker, options.edge, options.authority] as const
    : [options.authority, options.edge, options.broker] as const;
  const results = new Map<MacOsDeploymentComponent, unknown>();
  const completed: MacOsDeploymentComponent[] = [];

  for (const action of ordered) {
    try {
      const result = await action.execute();
      results.set(action.component, result);
      completed.push(action.component);
    } catch (error) {
      if (completed.length === 0) {
        throw deploymentError(options.operation, action.component, completed, false, false, "not-started", error);
      }
      let recoveryError: unknown;
      for (const completedComponent of [...completed].reverse()) {
        const completedAction = ordered.find((candidate) => candidate.component === completedComponent)!;
        try {
          await completedAction.recover();
        } catch (candidateError) {
          recoveryError ??= candidateError;
        }
      }
      if (recoveryError !== undefined) {
        throw deploymentError(options.operation, action.component, completed, true, false, "recovery-required", recoveryError);
      }
      throw deploymentError(options.operation, action.component, completed, true, true, "recovered", error);
    }
  }

  return {
    operation: options.operation,
    order: [ordered[0].component, ordered[1].component, ordered[2].component],
    authority: results.get("authority") as TAuthority,
    broker: results.get("broker") as TBroker,
    edge: results.get("edge") as TEdge
  };
}

/**
 * Coordinates the already-reviewed component executors as one host-owned
 * deployment transaction. Install, upgrade, and rollback run Edge first so
 * the HTTPS ingress cannot point at an absent Broker. Uninstall runs Broker
 * first, after its caller has completed any authority shutdown gate.
 *
 * This function does not construct plans, read secrets, authorize MCP input,
 * or invoke commands itself. Each action must be assembled by a host-owned
 * controller and must perform its own exact precondition and readback.
 */
export async function executeMacOsLaunchAgentDeployment<TEdge, TBroker>(
  options: MacOsLaunchAgentDeploymentOptions<TEdge, TBroker>
): Promise<MacOsLaunchAgentDeploymentResult<TEdge, TBroker>> {
  validateDeploymentOptions(options);
  const uninstall = options.operation === "uninstall";
  const ordered = uninstall
    ? [options.broker, options.edge] as const
    : [options.edge, options.broker] as const;
  const results = new Map<MacOsDeploymentComponent, unknown>();
  const completed: MacOsDeploymentComponent[] = [];

  for (const action of ordered) {
    try {
      const result = await action.execute();
      results.set(action.component, result);
      completed.push(action.component);
    } catch (error) {
      if (completed.length === 0) {
        throw deploymentError(options.operation, action.component, completed, false, false, "not-started", error);
      }
      const previous = ordered[0];
      try {
        await previous.recover();
      } catch (recoveryError) {
        throw deploymentError(options.operation, action.component, completed, true, false, "recovery-required", recoveryError);
      }
      throw deploymentError(options.operation, action.component, completed, true, true, "recovered", error);
    }
  }

  return {
    operation: options.operation,
    order: [ordered[0].component, ordered[1].component],
    edge: results.get("edge") as TEdge,
    broker: results.get("broker") as TBroker
  };
}

function validateDeploymentOptions<TEdge, TBroker>(
  options: MacOsLaunchAgentDeploymentOptions<TEdge, TBroker>
): void {
  if (options === null || typeof options !== "object" ||
      !isOperation(options.operation) || !isAction(options.edge, "edge") || !isAction(options.broker, "broker")) {
    throw new MacOsLaunchAgentDeploymentError(
      "COMMAND_FAILED",
      "macOS LaunchAgent deployment options are malformed",
      {
        operation: "install",
        failedComponent: "edge",
        completedComponents: [],
        recoveryAttempted: false,
        recoveryCompleted: false,
        recoveryState: "not-started"
      }
    );
  }
  if (options.edge.operation !== options.operation || options.broker.operation !== options.operation) {
    throw new MacOsLaunchAgentDeploymentError(
      "COMMAND_FAILED",
      "component operation does not match the deployment operation",
      {
        operation: options.operation,
        failedComponent: options.edge.operation === options.operation ? "broker" : "edge",
        completedComponents: [],
        recoveryAttempted: false,
        recoveryCompleted: false,
        recoveryState: "not-started"
      }
    );
  }
}

function validateAuthorityDeploymentOptions<TAuthority, TBroker, TEdge>(
  options: {
    operation: MacOsInstallOperation;
    authority: MacOsLaunchAgentComponentAction<TAuthority>;
    broker: MacOsLaunchAgentComponentAction<TBroker>;
    edge: MacOsLaunchAgentComponentAction<TEdge>;
  }
): void {
  if (options === null || typeof options !== "object" || !isOperation(options.operation) ||
      !isAction(options.authority, "authority") || !isAction(options.broker, "broker") ||
      !isAction(options.edge, "edge")) {
    throw new MacOsLaunchAgentDeploymentError(
      "COMMAND_FAILED",
      "three-component macOS LaunchAgent deployment options are malformed",
      {
        operation: "install",
        failedComponent: "authority",
        completedComponents: [],
        recoveryAttempted: false,
        recoveryCompleted: false,
        recoveryState: "not-started"
      }
    );
  }
  for (const component of [options.authority, options.broker, options.edge]) {
    if (component.operation !== options.operation) {
      throw new MacOsLaunchAgentDeploymentError(
        "COMMAND_FAILED",
        "component operation does not match the deployment operation",
        {
          operation: options.operation,
          failedComponent: component.component,
          completedComponents: [],
          recoveryAttempted: false,
          recoveryCompleted: false,
          recoveryState: "not-started"
        }
      );
    }
  }
}

function validatePlanDeployment(options: MacOsLaunchAgentPlanDeploymentOptions): void {
  if (options === null || typeof options !== "object" ||
      !isOperation(options.operation) ||
      !isEdgeActionSpec(options.edge) || !isBrokerActionSpec(options.broker)) {
    throw new MacOsInstallPlanError("INVALID_ARGUMENT", "macOS LaunchAgent plan deployment is malformed");
  }
  if (options.edge.plan.operation !== options.operation || options.broker.plan.operation !== options.operation) {
    throw new MacOsInstallPlanError("CONFIRMATION_REQUIRED", "component plans do not match the deployment operation");
  }
  const expectedRecovery = expectedRecoveryOperation(options.operation);
  if (options.edge.recovery.plan.operation !== expectedRecovery || options.broker.recovery.plan.operation !== expectedRecovery) {
    throw new MacOsInstallPlanError("SERVICE_MISMATCH", "component inverse plans do not match the deployment operation");
  }
  const plans = [options.edge.plan, options.broker.plan, options.edge.recovery.plan, options.broker.recovery.plan];
  const first = plans[0]!;
  const rest = plans.slice(1);
  for (const plan of rest) {
    if (plan.domain !== first.domain || plan.userHome !== first.userHome || plan.installRoot !== first.installRoot) {
      throw new MacOsInstallPlanError("SERVICE_MISMATCH", "LaunchAgent plans do not share one owner-domain deployment identity");
    }
  }
}

function validateAuthorityPlanDeployment(options: MacOsLaunchAgentAuthorityPlanDeploymentOptions): void {
  if (options === null || typeof options !== "object" || !isOperation(options.operation) ||
      !isAuthorityActionSpec(options.authority) || !isBrokerActionSpec(options.broker) ||
      !isEdgeActionSpec(options.edge)) {
    throw new MacOsInstallPlanError("INVALID_ARGUMENT", "three-component macOS LaunchAgent plan deployment is malformed");
  }
  const components = [options.authority, options.broker, options.edge];
  if (components.some((component) => component.plan.operation !== options.operation)) {
    throw new MacOsInstallPlanError("CONFIRMATION_REQUIRED", "component plans do not match the deployment operation");
  }
  const expectedRecovery = expectedRecoveryOperation(options.operation);
  if (components.some((component) => component.recovery.plan.operation !== expectedRecovery)) {
    throw new MacOsInstallPlanError("SERVICE_MISMATCH", "component inverse plans do not match the deployment operation");
  }
  const plans = components.flatMap((component) => [component.plan, component.recovery.plan]);
  const first = plans[0]!;
  for (const plan of plans.slice(1)) {
    if (plan.domain !== first.domain || plan.userHome !== first.userHome || plan.installRoot !== first.installRoot) {
      throw new MacOsInstallPlanError("SERVICE_MISMATCH", "LaunchAgent plans do not share one owner-domain deployment identity");
    }
  }
}

function assertReleaseMode(mode: MacOsLaunchAgentControllerMode, plans: readonly MacOsLaunchAgentPlan[]) {
  if (mode !== "production" && mode !== "development-probe") {
    throw new MacOsInstallPlanError("INVALID_ARGUMENT", "LaunchAgent controller mode is invalid");
  }
  if (mode === "development-probe") return;
  for (const plan of plans) {
    if (plan.signaturePolicy !== "developer-id" || plan.notarizationAssess === undefined ||
        plan.signature.teamIdentifier === undefined || plan.signature.cdHash === undefined) {
      throw new MacOsInstallPlanError("SIGNATURE_MISMATCH", "production LaunchAgent deployment requires Developer ID and notarization plans");
    }
  }
}

function expectedRecoveryOperation(operation: MacOsInstallOperation): MacOsInstallOperation {
  switch (operation) {
    case "install": return "uninstall";
    case "upgrade": return "rollback";
    case "rollback": return "upgrade";
    case "uninstall": return "install";
  }
}

function isEdgeActionSpec(value: unknown): value is MacOsEdgeLaunchAgentActionSpec {
  return value !== null && typeof value === "object" &&
    isEdgePlan((value as MacOsEdgeLaunchAgentActionSpec).plan) &&
    isEdgePlan((value as MacOsEdgeLaunchAgentActionSpec).recovery?.plan) &&
    isExecutionOptions((value as MacOsEdgeLaunchAgentActionSpec).execution) &&
    isExecutionOptions((value as MacOsEdgeLaunchAgentActionSpec).recovery?.execution);
}

function isBrokerActionSpec(value: unknown): value is MacOsBrokerLaunchAgentActionSpec {
  if (value === null || typeof value !== "object") return false;
  const spec = value as MacOsBrokerLaunchAgentActionSpec;
  if (!isBrokerPlan(spec.plan) || !isBrokerPlan(spec.recovery?.plan)) return false;
  return isBrokerExecution(spec.plan.operation, spec.execution) &&
    isBrokerExecution(spec.recovery.plan.operation, spec.recovery.execution);
}

function isAuthorityActionSpec(value: unknown): value is MacOsAuthorityLaunchAgentActionSpec {
  if (value === null || typeof value !== "object") return false;
  const spec = value as MacOsAuthorityLaunchAgentActionSpec;
  if (!isAuthorityPlan(spec.plan) || !isAuthorityPlan(spec.recovery?.plan)) return false;
  return isAuthorityExecution(spec.execution) && isAuthorityExecution(spec.recovery.execution);
}

function isEdgePlan(value: unknown): value is MacOsEdgeInstallPlan {
  return value !== null && typeof value === "object" && (value as MacOsEdgeInstallPlan).component === "mac-operator-edge";
}

function isBrokerPlan(value: unknown): value is MacOsInstallPlan {
  return value !== null && typeof value === "object" && (value as MacOsInstallPlan).component === "mac-operator-broker";
}

function isAuthorityPlan(value: unknown): value is MacOsAuthorityInstallPlan {
  return value !== null && typeof value === "object" && (value as MacOsAuthorityInstallPlan).component === "mac-operator-authority";
}

function isExecutionOptions(value: unknown): boolean {
  return value !== null && typeof value === "object" && typeof (value as { readExistingService?: unknown }).readExistingService === "function" &&
    typeof (value as { readback?: unknown }).readback === "function";
}

function isBrokerExecution(
  operation: MacOsInstallOperation,
  execution: MacOsBrokerLaunchAgentExecution | undefined
): boolean {
  if (execution === undefined) return false;
  if (operation === "uninstall") {
    const uninstall = execution.uninstall;
    return isExecutionOptions(uninstall) && typeof (uninstall as MacOsUninstallExecutionOptions).edgeId === "string" &&
      typeof (uninstall as MacOsUninstallExecutionOptions).disableGlobal === "function" &&
      typeof (uninstall as MacOsUninstallExecutionOptions).revokeEdge === "function" &&
      typeof (uninstall as MacOsUninstallExecutionOptions).authorityReadback === "function";
  }
  return isExecutionOptions(execution.install);
}

function isAuthorityExecution(value: unknown): boolean {
  return isExecutionOptions(value);
}

async function executeBrokerPlan(
  plan: MacOsInstallPlan,
  execution: MacOsBrokerLaunchAgentExecution
): Promise<MacOsInstallExecutionResult> {
  if (plan.operation === "uninstall") {
    if (execution.uninstall === undefined) {
      throw new MacOsInstallPlanError("AUTHORITY_FAILED", "Broker uninstall requires the authority-gated execution path");
    }
    return executeMacOsUninstallPlan(plan, {
      ...execution.uninstall,
      confirmOperation: "uninstall"
    });
  }
  if (execution.install === undefined) {
    throw new MacOsInstallPlanError("INVALID_ARGUMENT", "Broker install execution options are unavailable");
  }
  return executeMacOsInstallPlan(plan, {
    ...execution.install,
    confirmOperation: plan.operation
  });
}

function isAction<TResult>(
  value: unknown,
  component: MacOsDeploymentComponent
): value is MacOsLaunchAgentComponentAction<TResult> {
  if (value === null || typeof value !== "object") return false;
  const action = value as Partial<MacOsLaunchAgentComponentAction<TResult>>;
  return action.component === component && isOperation(action.operation) &&
    typeof action.execute === "function" && typeof action.recover === "function";
}

function isOperation(value: unknown): value is MacOsInstallOperation {
  return value === "install" || value === "upgrade" || value === "rollback" || value === "uninstall";
}

function deploymentError(
  operation: MacOsInstallOperation,
  failedComponent: MacOsDeploymentComponent,
  completedComponents: readonly MacOsDeploymentComponent[],
  recoveryAttempted: boolean,
  recoveryCompleted: boolean,
  recoveryState: MacOsDeploymentRecoveryState,
  cause: unknown
): MacOsLaunchAgentDeploymentError {
  return new MacOsLaunchAgentDeploymentError(
    recoveryCompleted ? "COMMAND_FAILED" : recoveryAttempted ? "RECOVERY_FAILED" : "COMMAND_FAILED",
    recoveryCompleted
      ? "macOS LaunchAgent deployment failed; the completed component was recovered"
      : recoveryAttempted
        ? "macOS LaunchAgent deployment failed and recovery requires operator action"
        : "macOS LaunchAgent deployment failed before any component completed",
    { operation, failedComponent, completedComponents: [...completedComponents], recoveryAttempted, recoveryCompleted, recoveryState },
    cause
  );
}
