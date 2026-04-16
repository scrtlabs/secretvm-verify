import { AttestationResult, makeResult, orderChecks } from "./types.js";

const POC_URL = "https://secretai.scrtlabs.com/api/quote-parse";

function curateResponse(body: any): Record<string, any> {
  const quote = (body && typeof body === "object" ? body.quote : null) ?? {};
  return {
    origin: body?.origin ?? null,
    proof_of_cloud: body?.proof_of_cloud ?? null,
    status: body?.status ?? null,
    machine_id: typeof quote === "object" ? quote.machine_id ?? null : null,
  };
}

/**
 * Verify a CPU quote against SCRT Labs' proof-of-cloud endpoint.
 *
 * The endpoint at https://secretai.scrtlabs.com/api/quote-parse echoes the
 * parsed quote and adds a `proof_of_cloud` boolean identifying the VM as
 * a Secret VM. This function posts the raw quote and reduces the response
 * to a display-friendly subset (origin, status, machine_id) — the 35 KB
 * `collateral` hex and the redundant quote dump are discarded.
 */
export async function checkProofOfCloud(
  quote: string,
): Promise<AttestationResult> {
  const checks: Record<string, boolean> = {};
  const report: Record<string, any> = {};
  const errors: string[] = [];

  let resp: Response;
  try {
    resp = await fetch(POC_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ quote: quote.trim() }),
    });
  } catch (e: any) {
    errors.push(`Failed to reach proof-of-cloud endpoint: ${e.message ?? e}`);
    checks.proof_of_cloud_verified = false;
    return makeResult("PROOF-OF-CLOUD", {
      checks: orderChecks(checks), report, errors,
    });
  }

  if (!resp.ok) {
    errors.push(`Proof-of-cloud endpoint returned HTTP ${resp.status}`);
    checks.proof_of_cloud_verified = false;
    return makeResult("PROOF-OF-CLOUD", {
      checks: orderChecks(checks), report, errors,
    });
  }

  let body: any;
  try {
    body = await resp.json();
  } catch (e: any) {
    errors.push(`Proof-of-cloud response was not valid JSON: ${e.message ?? e}`);
    checks.proof_of_cloud_verified = false;
    return makeResult("PROOF-OF-CLOUD", {
      checks: orderChecks(checks), report, errors,
    });
  }

  report.proof_of_cloud = curateResponse(body);
  const passed = body?.proof_of_cloud === true;
  checks.proof_of_cloud_verified = passed;
  if (!passed) {
    errors.push("Proof-of-cloud endpoint reported proof_of_cloud=false");
  }

  return makeResult("PROOF-OF-CLOUD", {
    valid: passed, checks: orderChecks(checks), report, errors,
  });
}
