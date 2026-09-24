import { BrokerError } from "@mac-operator/contracts";

export class AppSandboxRunAdmission {
  private active = false;
  private poisoned = false;

  get isPoisoned(): boolean {
    return this.poisoned;
  }

  begin(): (processBoundaryVerified: boolean) => void {
    if (this.poisoned) {
      throw new BrokerError("POLICY_DENIED", "App Sandbox task admission is disabled after an uncertain process outcome");
    }
    if (this.active) {
      throw new BrokerError("CONFLICT", "App Sandbox task admission allows only one active run", true);
    }

    this.active = true;
    let completed = false;
    return (processBoundaryVerified) => {
      if (completed) return;
      completed = true;
      this.active = false;
      if (processBoundaryVerified !== true) this.poisoned = true;
    };
  }
}
