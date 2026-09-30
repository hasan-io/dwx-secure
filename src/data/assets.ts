import type { Asset } from "../lib/types";

export const ASSETS: Record<string, Asset> = {
  "10.2.3.15": {
    ip: "10.2.3.15",
    hostname: "WKS-FIN-015",
    vlan: "Finance VLAN 23",
    department: "Finance",
    criticality: "High",
    os: "Windows 11 Enterprise 24H2",
    owner: "Finance IT Operations",
  },
  "10.0.5.20": {
    ip: "10.0.5.20",
    hostname: "WEB-PUB-02",
    vlan: "Public web server VLAN 10",
    department: "Digital Services",
    criticality: "Critical",
    os: "Ubuntu 24.04 LTS",
    owner: "Platform Engineering",
  },
  "10.2.9.44": {
    ip: "10.2.9.44",
    hostname: "WKS-HR-044",
    vlan: "HR VLAN 31",
    department: "Human Resources",
    criticality: "Medium",
    os: "Windows 11 Enterprise 24H2",
    owner: "HR IT Operations",
  },
  "10.4.7.33": {
    ip: "10.4.7.33",
    hostname: "WKS-LAB-033",
    vlan: "Research VLAN 47",
    department: "Research & Development",
    criticality: "Medium",
    os: "Ubuntu 24.04 LTS",
    owner: "R&D IT Operations",
  },
  "10.3.2.71": {
    ip: "10.3.2.71",
    hostname: "WKS-OPS-071",
    vlan: "Operations VLAN 12",
    department: "Operations",
    criticality: "High",
    os: "Windows 11 Enterprise 24H2",
    owner: "Operations IT",
  },
  "10.1.9.8": {
    ip: "10.1.9.8",
    hostname: "WKS-ENG-008",
    vlan: "Engineering VLAN 18",
    department: "Engineering",
    criticality: "Low",
    os: "Windows 11 Enterprise 24H2",
    owner: "Engineering IT",
  },
  "10.2.8.14": {
    ip: "10.2.8.14",
    hostname: "SRV-BACKUP-14",
    vlan: "Data Centre VLAN 8",
    department: "Infrastructure",
    criticality: "Medium",
    os: "Rocky Linux 9.4",
    owner: "Infrastructure Operations",
  },
};

export function assetOf(ip: string): Asset | undefined {
  return ASSETS[ip];
}
