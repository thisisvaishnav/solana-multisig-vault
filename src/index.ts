import express from "express";
import { PublicKey } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PROGRAM_ID = new PublicKey("11111111111111111111111111111111");

type ProposalAction = "transfer" | "set_data" | "memo";
type ProposalStatus = "pending" | "executed" | "cancelled";

type TransferParams = {
  to: string;
  amount: number;
};

type SetDataParams = {
  key: string;
  value: string;
};

type MemoParams = {
  content: string;
};

type ProposalParams = TransferParams | SetDataParams | MemoParams;

type ProposalSignature = {
  signer: string;
  createdAt: string;
};

type Proposal = {
  id: number;
  vaultId: number;
  proposer: string;
  action: ProposalAction;
  params: ProposalParams;
  status: ProposalStatus;
  signatures: ProposalSignature[];
  createdAt: string;
  executedAt?: string;
};

type Vault = {
  id: number;
  label: string;
  address: string;
  threshold: number;
  bump: number;
  signers: string[];
  createdAt: string;
  proposals: Proposal[];
  data: Record<string, string>;
};

const vaultsById = new Map<number, Vault>();
const vaultIdByAddress = new Map<string, number>();

let nextVaultId = 1;
let nextProposalId = 1;

function toCanonicalPubkey(value: unknown): string | null {
  if (typeof value !== "string" || value.trim().length === 0) {
    return null;
  }

  try {
    return new PublicKey(value.trim()).toBase58();
  } catch {
    return null;
  }
}

function parseVaultId(rawVaultId: string): number | null {
  const parsed = Number(rawVaultId);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }

  return parsed;
}

function parseProposalId(rawProposalId: string): number | null {
  const parsed = Number(rawProposalId);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }

  return parsed;
}

function deriveVaultAddress(signers: string[]): { address: string; bump: number } {
  const sortedSigners = [...signers].sort();
  const signerHash = crypto
    .createHash("sha256")
    .update(sortedSigners.join(":"))
    .digest();

  const [pda, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault"), signerHash],
    PROGRAM_ID,
  );

  return {
    address: pda.toBase58(),
    bump,
  };
}

function verifyDetachedSignature(
  signer: string,
  signature: string,
  message: string,
): boolean {
  try {
    const publicKey = new PublicKey(signer).toBytes();
    const signatureBytes = bs58.decode(signature);
    const messageBytes = new TextEncoder().encode(message);
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKey);
  } catch {
    return false;
  }
}

function findVaultOr404(vaultIdRaw: string, res: express.Response): Vault | null {
  const vaultId = parseVaultId(vaultIdRaw);
  if (vaultId === null) {
    res.status(404).json({ error: "Vault not found" });
    return null;
  }

  const vault = vaultsById.get(vaultId);
  if (!vault) {
    res.status(404).json({ error: "Vault not found" });
    return null;
  }

  return vault;
}

function findProposalOr404(
  vault: Vault,
  proposalIdRaw: string,
  res: express.Response,
): Proposal | null {
  const proposalId = parseProposalId(proposalIdRaw);
  if (proposalId === null) {
    res.status(404).json({ error: "Proposal not found" });
    return null;
  }

  const proposal = vault.proposals.find((item) => item.id === proposalId);
  if (!proposal) {
    res.status(404).json({ error: "Proposal not found" });
    return null;
  }

  return proposal;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

app.post("/api/vault/create", (req, res) => {
  const { signers, threshold, label } = req.body as {
    signers?: unknown;
    threshold?: unknown;
    label?: unknown;
  };

  if (!Array.isArray(signers) || signers.length < 2) {
    res.status(400).json({ error: "Invalid signers" });
    return;
  }

  const canonicalSigners: string[] = [];
  for (const signer of signers) {
    const canonical = toCanonicalPubkey(signer);
    if (!canonical) {
      res.status(400).json({ error: "Invalid signers" });
      return;
    }
    canonicalSigners.push(canonical);
  }

  const uniqueSigners = new Set(canonicalSigners);
  if (uniqueSigners.size !== canonicalSigners.length) {
    res.status(400).json({ error: "Invalid signers" });
    return;
  }

  if (!Number.isInteger(threshold) || (threshold as number) < 1) {
    res.status(400).json({ error: "Invalid threshold" });
    return;
  }

  if ((threshold as number) > canonicalSigners.length) {
    res.status(400).json({ error: "Invalid threshold" });
    return;
  }

  if (typeof label !== "string" || label.trim().length === 0) {
    res.status(400).json({ error: "Invalid label" });
    return;
  }

  const sortedSigners = [...canonicalSigners].sort();
  const { address, bump } = deriveVaultAddress(sortedSigners);

  if (vaultIdByAddress.has(address)) {
    res.status(409).json({ error: "Vault already exists" });
    return;
  }

  const now = new Date().toISOString();
  const vault: Vault = {
    id: nextVaultId++,
    label: label.trim(),
    address,
    threshold: threshold as number,
    bump,
    signers: sortedSigners,
    createdAt: now,
    proposals: [],
    data: {},
  };

  vaultsById.set(vault.id, vault);
  vaultIdByAddress.set(vault.address, vault.id);

  res.status(201).json({
    id: vault.id,
    label: vault.label,
    address: vault.address,
    threshold: vault.threshold,
    bump: vault.bump,
    signers: vault.signers,
    createdAt: vault.createdAt,
  });
});

app.get("/api/vault/:vaultId", (req, res) => {
  const vault = findVaultOr404(req.params.vaultId, res);
  if (!vault) {
    return;
  }

  res.status(200).json({
    id: vault.id,
    label: vault.label,
    address: vault.address,
    threshold: vault.threshold,
    bump: vault.bump,
    signers: vault.signers,
    proposalCount: vault.proposals.length,
    createdAt: vault.createdAt,
  });
});

app.post("/api/vault/:vaultId/propose", (req, res) => {
  const vault = findVaultOr404(req.params.vaultId, res);
  if (!vault) {
    return;
  }

  const { proposer, action, params } = req.body as {
    proposer?: unknown;
    action?: unknown;
    params?: unknown;
  };

  const canonicalProposer = toCanonicalPubkey(proposer);
  if (!canonicalProposer || !vault.signers.includes(canonicalProposer)) {
    res.status(403).json({ error: "Not a vault signer" });
    return;
  }

  if (action !== "transfer" && action !== "set_data" && action !== "memo") {
    res.status(400).json({ error: "Invalid action or params" });
    return;
  }

  if (!isPlainObject(params)) {
    res.status(400).json({ error: "Invalid action or params" });
    return;
  }

  let validatedParams: ProposalParams;

  if (action === "transfer") {
    const to = toCanonicalPubkey(params.to);
    const amount = params.amount;
    if (!to || typeof amount !== "number" || !Number.isFinite(amount) || amount <= 0) {
      res.status(400).json({ error: "Invalid action or params" });
      return;
    }
    validatedParams = { to, amount };
  } else if (action === "set_data") {
    const key = params.key;
    const value = params.value;
    if (
      typeof key !== "string" ||
      key.trim().length === 0 ||
      typeof value !== "string" ||
      value.trim().length === 0
    ) {
      res.status(400).json({ error: "Invalid action or params" });
      return;
    }
    validatedParams = { key, value };
  } else {
    const content = params.content;
    if (typeof content !== "string" || content.trim().length === 0) {
      res.status(400).json({ error: "Invalid action or params" });
      return;
    }
    validatedParams = { content };
  }

  const proposal: Proposal = {
    id: nextProposalId++,
    vaultId: vault.id,
    proposer: canonicalProposer,
    action,
    params: validatedParams,
    status: "pending",
    signatures: [],
    createdAt: new Date().toISOString(),
  };

  vault.proposals.push(proposal);

  res.status(201).json(proposal);
});

app.post("/api/vault/:vaultId/proposals/:proposalId/approve", (req, res) => {
  const vault = findVaultOr404(req.params.vaultId, res);
  if (!vault) {
    return;
  }

  const proposal = findProposalOr404(vault, req.params.proposalId, res);
  if (!proposal) {
    return;
  }

  if (proposal.status === "executed") {
    res.status(409).json({ error: "Proposal already executed" });
    return;
  }

  if (proposal.status === "cancelled") {
    res.status(409).json({ error: "Proposal already cancelled" });
    return;
  }

  const { signer, signature } = req.body as {
    signer?: unknown;
    signature?: unknown;
  };

  const canonicalSigner = toCanonicalPubkey(signer);
  if (!canonicalSigner || !vault.signers.includes(canonicalSigner)) {
    res.status(403).json({ error: "Not a vault signer" });
    return;
  }

  if (proposal.signatures.some((entry) => entry.signer === canonicalSigner)) {
    res.status(409).json({ error: "Already signed" });
    return;
  }

  if (typeof signature !== "string" || signature.trim().length === 0) {
    res.status(400).json({ error: "Invalid signature" });
    return;
  }

  const message = `approve:${proposal.id}`;
  const isValidSignature = verifyDetachedSignature(
    canonicalSigner,
    signature.trim(),
    message,
  );

  if (!isValidSignature) {
    res.status(400).json({ error: "Invalid signature" });
    return;
  }

  proposal.signatures.push({
    signer: canonicalSigner,
    createdAt: new Date().toISOString(),
  });

  if (proposal.status === "pending" && proposal.signatures.length >= vault.threshold) {
    if (proposal.action === "set_data") {
      const setDataParams = proposal.params as SetDataParams;
      vault.data[setDataParams.key] = setDataParams.value;
    }

    proposal.status = "executed";
    proposal.executedAt = new Date().toISOString();
  }

  res.status(200).json(proposal);
});

app.get("/api/vault/:vaultId/proposals", (req, res) => {
  const vault = findVaultOr404(req.params.vaultId, res);
  if (!vault) {
    return;
  }

  const statusFilter = req.query.status;
  if (
    statusFilter !== undefined &&
    statusFilter !== "pending" &&
    statusFilter !== "executed" &&
    statusFilter !== "cancelled"
  ) {
    res.status(400).json({ error: "Invalid status filter" });
    return;
  }

  const proposals =
    statusFilter === undefined
      ? vault.proposals
      : vault.proposals.filter((proposal) => proposal.status === statusFilter);

  res.status(200).json(proposals);
});

app.get("/api/vault/:vaultId/proposals/:proposalId", (req, res) => {
  const vault = findVaultOr404(req.params.vaultId, res);
  if (!vault) {
    return;
  }

  const proposal = findProposalOr404(vault, req.params.proposalId, res);
  if (!proposal) {
    return;
  }

  res.status(200).json(proposal);
});

app.post("/api/vault/:vaultId/proposals/:proposalId/cancel", (req, res) => {
  const vault = findVaultOr404(req.params.vaultId, res);
  if (!vault) {
    return;
  }

  const proposal = findProposalOr404(vault, req.params.proposalId, res);
  if (!proposal) {
    return;
  }

  if (proposal.status === "executed") {
    res.status(409).json({ error: "Proposal already executed" });
    return;
  }

  if (proposal.status === "cancelled") {
    res.status(409).json({ error: "Proposal already cancelled" });
    return;
  }

  const { signer, signature } = req.body as {
    signer?: unknown;
    signature?: unknown;
  };

  const canonicalSigner = toCanonicalPubkey(signer);
  if (!canonicalSigner || canonicalSigner !== proposal.proposer) {
    res.status(403).json({ error: "Only the proposer can cancel" });
    return;
  }

  if (typeof signature !== "string" || signature.trim().length === 0) {
    res.status(400).json({ error: "Invalid signature" });
    return;
  }

  const message = `cancel:${proposal.id}`;
  const isValidSignature = verifyDetachedSignature(
    canonicalSigner,
    signature.trim(),
    message,
  );

  if (!isValidSignature) {
    res.status(400).json({ error: "Invalid signature" });
    return;
  }

  proposal.status = "cancelled";
  res.status(200).json(proposal);
});

app.get("/api/vault/:vaultId/data", (req, res) => {
  const vault = findVaultOr404(req.params.vaultId, res);
  if (!vault) {
    return;
  }

  res.status(200).json({ data: vault.data });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
