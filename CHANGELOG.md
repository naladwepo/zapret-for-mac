# Changelog

## 0.2.0 — macOS packet transport and Happ split routing

- native PFLOG/BPF packet datapath for macOS;
- `cloud-gaming` strategy combining Discord, YouTube and game traffic;
- Discord connectivity suite and safer full-sweep `autopick`;
- VPN detection based on tunnel default routes, not a hard-coded `utun8`;
- Happ deep-link routing adapter;
- Happ-only split-routing adapter with active-client checks;
- launchd installation with `--allow-vpn` and root-exempt VPN transport;
- PFLOG interception restricted to the physical uplink, leaving VPN-routed traffic in `utun`;
- PF/BPF live integration coverage, diagnostics and recovery documentation.

The router intentionally supports Happ only. Other VPN clients are not modified
automatically because macOS has no common split-tunnel configuration API.
