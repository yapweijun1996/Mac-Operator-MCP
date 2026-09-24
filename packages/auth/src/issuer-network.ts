import { lookup } from "node:dns";
import { Resolver } from "node:dns/promises";
import { Agent, setGlobalDispatcher } from "undici";

/** Personal host router caches NXDOMAIN for new subdomains. Resolve only the
 * configured public issuer through public DNS; HTTPS identity checks stay on. */
export function configureIssuerNetwork(hostname: string) {
  const resolver = new Resolver({ timeout: 1500, tries: 1 });
  resolver.setServers(["1.1.1.1", "8.8.8.8"]);
  const agent = new Agent({ connect: { lookup: (name, options, callback) => {
    if (name !== hostname) { lookup(name, options, callback); return; }
    void resolver.resolve4(name).then(addresses => {
      if (!addresses[0]) throw new Error("Issuer DNS unavailable");
      if (options.all) callback(null, addresses.map(address => ({ address, family: 4 })));
      else callback(null, addresses[0], 4);
    }).catch(() => callback(new Error("Issuer DNS unavailable"), "", 4));
  } } });
  setGlobalDispatcher(agent);
  return agent;
}
