export interface ChainConfig {
  chainId: number;
  name: string;
  registryAddress: string;
}

const DEFAULT_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
const SEPOLIA_REGISTRY = "0x8004A818BFB912233c491871b3d84c89A494BD9e";

const CHAINS: Record<string, ChainConfig> = {
  ethereum:  { chainId: 1,        name: "Ethereum",        registryAddress: DEFAULT_REGISTRY },
  base:      { chainId: 8453,     name: "Base",            registryAddress: DEFAULT_REGISTRY },
  arbitrum:  { chainId: 42161,    name: "Arbitrum",        registryAddress: DEFAULT_REGISTRY },
  sepolia:   { chainId: 11155111, name: "Sepolia",         registryAddress: SEPOLIA_REGISTRY },
  polygon:   { chainId: 137,      name: "Polygon",         registryAddress: DEFAULT_REGISTRY },
  bnb:       { chainId: 56,       name: "BNB Smart Chain", registryAddress: DEFAULT_REGISTRY },
  gnosis:    { chainId: 100,      name: "Gnosis",          registryAddress: DEFAULT_REGISTRY },
  linea:     { chainId: 59144,    name: "Linea",           registryAddress: DEFAULT_REGISTRY },
  taiko:     { chainId: 167000,   name: "Taiko",           registryAddress: DEFAULT_REGISTRY },
  celo:      { chainId: 42220,    name: "Celo",            registryAddress: DEFAULT_REGISTRY },
  avalanche: { chainId: 43114,    name: "Avalanche",       registryAddress: DEFAULT_REGISTRY },
  optimism:  { chainId: 10,       name: "Optimism",        registryAddress: DEFAULT_REGISTRY },
  abstract:  { chainId: 2741,     name: "Abstract",        registryAddress: DEFAULT_REGISTRY },
  megaeth:   { chainId: 1000001,  name: "MegaETH",         registryAddress: DEFAULT_REGISTRY },
  mantle:    { chainId: 5000,     name: "Mantle",          registryAddress: DEFAULT_REGISTRY },
  soneium:   { chainId: 1946,     name: "Soneium",         registryAddress: DEFAULT_REGISTRY },
  xlayer:    { chainId: 196,      name: "X Layer",         registryAddress: DEFAULT_REGISTRY },
  metis:     { chainId: 1088,     name: "Metis",           registryAddress: DEFAULT_REGISTRY },
};

export function getChainConfig(chain: string): ChainConfig {
  const config = CHAINS[chain.toLowerCase()];
  if (!config) {
    const valid = Object.keys(CHAINS).join(", ");
    throw new Error(`Unknown chain "${chain}". Supported: ${valid}`);
  }
  return config;
}

/**
 * Resolve the RPC URL for a chain. Priority:
 * 1. SECRETVM_RPC_<CHAIN> (e.g. SECRETVM_RPC_BASE)
 * 2. SECRETVM_RPC_URL (generic fallback)
 *
 * Throws if no RPC URL is configured.
 */
export function getRpcUrl(chain: string): string {
  const envKey = `SECRETVM_RPC_${chain.toUpperCase()}`;
  if (process.env[envKey]) return process.env[envKey]!;
  if (process.env.SECRETVM_RPC_URL) return process.env.SECRETVM_RPC_URL;
  throw new Error(
    `No RPC URL configured for ${chain}. ` +
    `Set the ${envKey} or SECRETVM_RPC_URL environment variable.`
  );
}

export function listChains(): string[] {
  return Object.keys(CHAINS);
}
