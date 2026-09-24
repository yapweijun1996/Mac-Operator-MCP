import {
  AllowlistedPrivilegedHelper,
  type PrivilegedHelperAdapter
} from "./privileged-helper.js";
import {
  PrivilegedPackageInstallAdapter,
  type PrivilegedPackageInstallAdapterOptions
} from "./privileged-package-install.js";
import {
  PrivilegedPowerAdapter,
  type PrivilegedPowerAdapterOptions
} from "./privileged-power.js";
import {
  PrivilegedServiceControlAdapter,
  type PrivilegedServiceControlAdapterOptions
} from "./privileged-service-control.js";

export interface PrivilegedHelperAdaptersOptions {
  serviceControl?: PrivilegedServiceControlAdapterOptions;
  packageInstall?: PrivilegedPackageInstallAdapterOptions;
  power?: PrivilegedPowerAdapterOptions;
}

/**
 * Compose the independently gated host adapters into one helper projection.
 * Each operation keeps its own enablement, fixed executable boundary, and
 * readback contract; an available service adapter cannot imply package or
 * power availability.
 */
export function createPrivilegedHelperAdapter(options: PrivilegedHelperAdaptersOptions = {}): PrivilegedHelperAdapter {
  const serviceControl = new PrivilegedServiceControlAdapter(options.serviceControl);
  const packageInstall = new PrivilegedPackageInstallAdapter(options.packageInstall);
  const power = new PrivilegedPowerAdapter(options.power);
  return new AllowlistedPrivilegedHelper({
    ...(serviceControl.available ? {
      service_control: (command, control) => serviceControl.execute(command, control),
      service_control_readback: (request, control) => serviceControl.readback(request, control)
    } : {}),
    ...(packageInstall.available ? {
      package_install: (command, control) => packageInstall.execute(command, control),
      package_install_readback: (request, control) => packageInstall.readback(request, control)
    } : {}),
    ...(power.available ? {
      power: (command, control) => power.execute(command, control),
      power_readback: (request, control) => power.readback(request, control)
    } : {})
  });
}
