import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from "ethereum-cryptography/bip39/index.js";
import { wordlist } from "ethereum-cryptography/bip39/wordlists/english.js";
import { HDKey } from "ethereum-cryptography/hdkey.js";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { secp256k1 } from "ethereum-cryptography/secp256k1.js";
import { bytesToHex, utf8ToBytes } from "ethereum-cryptography/utils.js";

export const EVM_DERIVATION_PATH = "m/44'/60'/0'/0/0";

export function checksumAddress(hexAddress) {
  if (!/^[0-9a-f]{40}$/i.test(hexAddress)) throw new Error("Invalid EVM address bytes.");
  const lower = hexAddress.toLowerCase();
  const hash = bytesToHex(keccak256(utf8ToBytes(lower)));
  return `0x${Array.from(lower, (character, index) => /[a-f]/.test(character) && Number.parseInt(hash[index], 16) >= 8 ? character.toUpperCase() : character).join("")}`;
}

export function walletFromMnemonic(mnemonic) {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error("Invalid BIP-39 mnemonic.");
  const seed = mnemonicToSeedSync(mnemonic);
  const root = HDKey.fromMasterSeed(seed);
  const derived = root.derive(EVM_DERIVATION_PATH);
  try {
    if (!derived.publicKey) throw new Error("Could not derive the EVM public key.");
    const uncompressed = secp256k1.ProjectivePoint.fromHex(derived.publicKey).toRawBytes(false);
    const addressBytes = keccak256(uncompressed.slice(1)).slice(-20);
    return { mnemonic, address: checksumAddress(bytesToHex(addressBytes)), path: EVM_DERIVATION_PATH };
  } finally {
    seed.fill(0); derived.wipePrivateData(); root.wipePrivateData();
  }
}

export function generateWallet() {
  const entropy = new Uint8Array(16);
  crypto.getRandomValues(entropy);
  try { return walletFromMnemonic(entropyToMnemonic(entropy, wordlist)); }
  finally { entropy.fill(0); }
}

export function mnemonicEntropyBits(mnemonic) {
  return mnemonicToEntropy(mnemonic, wordlist).length * 8;
}
