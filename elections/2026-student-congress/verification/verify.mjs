#!/usr/bin/env node
// Student delegate lottery — independent verifier. Node 18 or later, no dependencies.
// Usage: node verify.mjs [--online]     (run inside the verification/ folder)
// Generated from the lottery server's own source files; do not edit.
import { createHash, createHmac } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ---- studentLottery.algorithm.js ----
/**
 * Student delegate lottery — deterministic selection.
 *
 * Two versions, which differ only in how a pool smaller than its quota is treated:
 *   an-student-lottery/v1  strict: any pool with fewer eligible entries than mandates rejects the whole draw.
 *   an-student-lottery/v2  partial fulfilment: such a pool selects everyone eligible ("automatic") and the
 *                          remaining mandates stay vacant; larger pools are ranked as before ("random").
 * The seed, the tickets and the ranking are identical in both versions, so the Bitcoin selection rule is
 * unchanged. A lottery keeps the version it was created with; it is part of the commitment.
 *
 * Pure: no database, no network, no clock, no Math.random. The only import is node:crypto.
 * Specification: docs/student-lottery/04-lottery-correctness-and-verification.md §5.
 * This file is inlined into the published verify.mjs, so keep it dependency-free.
 */

const ALGORITHM_V1 = "an-student-lottery/v1";
const ALGORITHM_V2 = "an-student-lottery/v2";
/** Every version this code can draw and verify. */
const SUPPORTED_ALGORITHMS = Object.freeze([ALGORITHM_V1, ALGORITHM_V2]);
/** The version given to new lotteries. */
const CURRENT_ALGORITHM = ALGORITHM_V2;
/** @deprecated the original single version; kept for callers that mean v1 explicitly. */
const ALGORITHM_ID = ALGORITHM_V1;
const LOTTERY_GENDERS = ["male", "female"];

/** Selection method of a v2 pool: everyone eligible fits ("automatic"), or the ranking decides ("random"). */
const SELECTION_METHODS = Object.freeze({ automatic: "automatic", random: "random" });

/**
 * The domain strings keep their v1 spelling in every version: changing them would change the tickets,
 * i.e. the Bitcoin selection rule, which v2 deliberately keeps.
 */
const SEED_DOMAIN = "an-student-lottery/v1/seed";
const TICKET_DOMAIN = "an-student-lottery/v1/ticket";
const HEX_64 = /^[0-9a-f]{64}$/;
/** No newline or separator characters, so the ticket message cannot be ambiguous. */
const ENTRY_ID = /^[A-Za-z0-9_-]{1,64}$/;
const GROUP_CODE = /^[A-Z0-9_-]{1,32}$/;

class LotteryInputError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "LotteryInputError";
    this.code = code;
    this.details = details;
  }
}

function inputError(code, message, details) {
  return new LotteryInputError(code, message, details);
}

/** seed = SHA-256("an-student-lottery/v1/seed\n" + commitmentSha256 + "\n" + blockHash) */
function deriveSeed(commitmentSha256, blockHash) {
  if (typeof commitmentSha256 !== "string" || !HEX_64.test(commitmentSha256)) {
    throw inputError("INVALID_COMMITMENT_HASH", "commitmentSha256 must be 64 lowercase hex characters");
  }
  if (typeof blockHash !== "string" || !HEX_64.test(blockHash)) {
    throw inputError("INVALID_BLOCK_HASH", "blockHash must be 64 lowercase hex characters");
  }
  return createHash("sha256").update(`${SEED_DOMAIN}\n${commitmentSha256}\n${blockHash}`, "utf8").digest();
}

function assertSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw inputError("INVALID_SEED", "seed must be a 32-byte Buffer produced by deriveSeed()");
  }
}

/** ticket = HMAC-SHA256(seed, "an-student-lottery/v1/ticket\n" + group + "\n" + gender + "\n" + entryId), hex */
function ticket(seed, group, gender, entryId) {
  assertSeed(seed);
  if (typeof group !== "string" || !GROUP_CODE.test(group)) {
    throw inputError("INVALID_GROUP_CODE", "group code must match [A-Z0-9_-]{1,32}", { group });
  }
  if (!LOTTERY_GENDERS.includes(gender)) {
    throw inputError("INVALID_GENDER", "gender must be male or female", { gender });
  }
  if (typeof entryId !== "string" || !ENTRY_ID.test(entryId)) {
    throw inputError("INVALID_ENTRY_ID", "entryId must match [A-Za-z0-9_-]{1,64}", { entryId });
  }
  return createHmac("sha256", seed).update(`${TICKET_DOMAIN}\n${group}\n${gender}\n${entryId}`, "utf8").digest("hex");
}

/** Ascending by ticket (lowercase hex compares like the number); ties by entryId. Never by input position. */
function compareRanked(a, b) {
  if (a.ticket !== b.ticket) return a.ticket < b.ticket ? -1 : 1;
  if (a.entryId !== b.entryId) return a.entryId < b.entryId ? -1 : 1;
  return 0;
}

function assertSupportedAlgorithm(algorithm) {
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw inputError("UNSUPPORTED_ALGORITHM", `algorithm ${algorithm} is not one of ${SUPPORTED_ALGORITHMS.join(", ")}`, { algorithm });
  }
  return algorithm;
}

/** "strict" (v1) or "partial" (v2): the quota policy of an algorithm version. */
function quotaPolicy(algorithm) {
  return assertSupportedAlgorithm(algorithm) === ALGORITHM_V1 ? "strict" : "partial";
}

/**
 * Expected outcome of one pool under the partial policy. Pure arithmetic, shared by the preflight,
 * the draw and the verifier so that all three agree.
 */
function poolPlan(available, quota) {
  const selected = Math.min(available, quota);
  return {
    available,
    quota,
    selected,
    vacant: Math.max(0, quota - available),
    reserve: Math.max(0, available - quota),
    method: available > quota && quota > 0 ? SELECTION_METHODS.random : SELECTION_METHODS.automatic,
  };
}

function normalizeGroups(groups) {
  if (!Array.isArray(groups) || groups.length === 0) {
    throw inputError("INVALID_GROUPS", "groups must be a non-empty array");
  }
  const codes = new Set();
  const orders = new Set();
  const normalized = groups.map((group) => {
    const code = group?.code;
    if (typeof code !== "string" || !GROUP_CODE.test(code)) {
      throw inputError("INVALID_GROUP_CODE", "group code must match [A-Z0-9_-]{1,32}", { group: code });
    }
    if (codes.has(code)) throw inputError("DUPLICATE_GROUP", `group ${code} is listed twice`, { group: code });
    codes.add(code);
    if (!Number.isSafeInteger(group.order) || group.order < 1) {
      throw inputError("INVALID_GROUP_ORDER", `group ${code} needs a positive integer order`, { group: code });
    }
    if (orders.has(group.order)) {
      throw inputError("DUPLICATE_GROUP_ORDER", `order ${group.order} is used twice`, { group: code });
    }
    orders.add(group.order);
    const quota = {};
    for (const gender of LOTTERY_GENDERS) {
      const value = group.quota?.[gender];
      if (!Number.isSafeInteger(value) || value < 0) {
        throw inputError("INVALID_QUOTA", `group ${code} needs a non-negative integer ${gender} quota`, { group: code, gender });
      }
      quota[gender] = value;
    }
    return { code, order: group.order, quota };
  });
  return normalized.sort((a, b) => a.order - b.order);
}

/**
 * Rank every pool and split it into selected and reserve.
 *
 * @param {{ groups: {code, order, quota: {male, female}}[], entries: {entryId, group, gender}[], seed: Buffer,
 *           algorithm?: string }} input   `algorithm` defaults to v1 (the strict rule) for older callers.
 * @returns {{ code, order, pools: { gender, quota, available?, method?, vacant?,
 *             selected: {rank, entryId, ticket}[], reserve: {rank, entryId, ticket}[] }[] }[]}
 *             (`available`, `method` and `vacant` only in v2)
 *
 * v1 (strict): every pool is checked before anything is selected. One short pool rejects the whole draw
 * with QUOTA_UNFILLED; nothing is partially selected and no mandate moves to another pool.
 * v2 (partial): each pool selects min(available, quota) by rank; the rest of its mandates stay vacant.
 * No mandate ever moves to another gender or group. Every pool is ranked the same way in both versions,
 * so an "automatic" pool still has a stable, reproducible order.
 */
function draw({ groups, entries, seed, algorithm = ALGORITHM_V1 }) {
  assertSeed(seed);
  const policy = quotaPolicy(algorithm);
  const orderedGroups = normalizeGroups(groups);
  if (!Array.isArray(entries)) throw inputError("INVALID_ENTRIES", "entries must be an array");

  const pools = new Map();
  for (const group of orderedGroups) {
    for (const gender of LOTTERY_GENDERS) pools.set(`${group.code}\n${gender}`, []);
  }
  const seen = new Set();
  for (const entry of entries) {
    const entryId = entry?.entryId;
    if (typeof entryId !== "string" || !ENTRY_ID.test(entryId)) {
      throw inputError("INVALID_ENTRY_ID", "entryId must match [A-Za-z0-9_-]{1,64}", { entryId });
    }
    if (seen.has(entryId)) throw inputError("DUPLICATE_ENTRY", `entry ${entryId} appears twice`, { entryId });
    seen.add(entryId);
    if (!LOTTERY_GENDERS.includes(entry.gender)) {
      throw inputError("INVALID_GENDER", `entry ${entryId} has no valid gender`, { entryId });
    }
    const pool = pools.get(`${entry.group}\n${entry.gender}`);
    if (!pool) throw inputError("UNKNOWN_GROUP", `entry ${entryId} belongs to an unknown group`, { entryId, group: entry.group });
    pool.push(entryId);
  }

  const shortfalls = [];
  for (const group of orderedGroups) {
    for (const gender of LOTTERY_GENDERS) {
      const eligible = pools.get(`${group.code}\n${gender}`).length;
      if (eligible < group.quota[gender]) {
        shortfalls.push({ group: group.code, gender, quota: group.quota[gender], eligible });
      }
    }
  }
  if (policy === "strict" && shortfalls.length > 0) {
    const first = shortfalls[0];
    throw inputError(
      "QUOTA_UNFILLED",
      `QUOTA_UNFILLED ${first.group}/${first.gender}: ${first.eligible} eligible for ${first.quota} mandates`,
      { shortfalls },
    );
  }

  return orderedGroups.map((group) => ({
    code: group.code,
    order: group.order,
    pools: LOTTERY_GENDERS.map((gender) => {
      const ranked = pools.get(`${group.code}\n${gender}`)
        .map((entryId) => ({ entryId, ticket: ticket(seed, group.code, gender, entryId) }))
        .sort(compareRanked);
      const quota = group.quota[gender];
      const plan = poolPlan(ranked.length, quota);
      const withRank = (list) => list.map((item, index) => ({ rank: index + 1, entryId: item.entryId, ticket: item.ticket }));
      const selected = withRank(ranked.slice(0, plan.selected));
      const reserve = withRank(ranked.slice(plan.selected));
      // v1 pools keep exactly their original shape.
      if (policy === "strict") return { gender, quota, selected, reserve };
      return { gender, quota, available: plan.available, method: plan.method, vacant: plan.vacant, selected, reserve };
    }),
  }));
}

/** Flat reveal sequence: groups by order, male selections by rank, then female selections by rank. */
function revealOrder(drawResult) {
  const sequence = [];
  for (const group of drawResult) {
    for (const pool of group.pools) {
      for (const item of pool.selected) {
        sequence.push({
          revealIndex: sequence.length + 1,
          group: group.code,
          gender: pool.gender,
          rank: item.rank,
          entryId: item.entryId,
          ticket: item.ticket,
        });
      }
    }
  }
  return sequence;
}

// ---- studentLottery.bitcoin.js ----
/**
 * Student delegate lottery — Bitcoin block header verification and the block selection rule.
 *
 * Pure: no network, no database, no clock. The only import is node:crypto.
 * Specification: docs/student-lottery/04-lottery-correctness-and-verification.md §4.
 * This file is inlined into the published verify.mjs, so keep it dependency-free.
 *
 * Trust boundary. These functions prove that a run of headers is internally valid: each header hashes
 * below its own target, links to the one before it, keeps the mainnet difficulty rules inside the run,
 * and carries enough work to be far too expensive to fabricate. They do NOT prove that the run is part
 * of the most-work Bitcoin chain, and block heights are claims (a header does not contain its height).
 * Chain membership must be confirmed against independent sources or a full node.
 */

const BLOCK_RULE_TYPE = "first-block-mtp-gte";
const BITCOIN_NETWORK = "bitcoin-mainnet";
const HEADER_HEX_LENGTH = 160;

const HEADER_HEX = /^[0-9a-f]{160}$/;
const BLOCK_HASH_HEX = /^[0-9a-f]{64}$/;

class BitcoinVerificationError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "BitcoinVerificationError";
    this.code = code;
    this.details = details;
  }
}

function chainError(code, message, details) {
  return new BitcoinVerificationError(code, message, details);
}

/**
 * Decode a compact difficulty value (nBits) into the 256-bit target, with the consensus rejections of
 * Bitcoin Core's arith_uint256::SetCompact: negative, zero and overflowing encodings are invalid.
 */
function bitsToTarget(bits) {
  if (!Number.isInteger(bits) || bits < 0 || bits > 0xffffffff) {
    throw chainError("INVALID_BITS", "nBits must be an unsigned 32-bit integer");
  }
  const exponent = bits >>> 24;
  const mantissa = bits & 0x007fffff;
  if (bits & 0x00800000) throw chainError("INVALID_BITS", "nBits encodes a negative target");
  if (mantissa === 0) throw chainError("INVALID_BITS", "nBits encodes a zero target");
  if (exponent > 34 || (mantissa > 0xff && exponent > 33) || (mantissa > 0xffff && exponent > 32)) {
    throw chainError("INVALID_BITS", "nBits overflows 256 bits");
  }
  const target = exponent <= 3
    ? BigInt(mantissa) >> BigInt(8 * (3 - exponent))
    : BigInt(mantissa) << BigInt(8 * (exponent - 3));
  if (target === 0n) throw chainError("INVALID_BITS", "nBits encodes a zero target");
  return target;
}

/**
 * Bitcoin mainnet parameters used by algorithm an-student-lottery/v1.
 *
 * minWorkTarget is an absolute floor on difficulty (compact 0x1800ffff, difficulty 2^40 ≈ 1.1e12).
 * Mainnet has been above it since early 2018. It stops a header run mined at toy difficulty from passing
 * offline checks even if the published anchor were itself fabricated.
 */
const BITCOIN_MAINNET = Object.freeze({
  network: BITCOIN_NETWORK,
  powLimit: bitsToTarget(0x1d00ffff),
  minWorkTarget: bitsToTarget(0x1800ffff),
  retargetInterval: 2016,
  maxRetargetFactor: 4n,
  medianTimeSpan: 11,
});

function reverseHex(hex) {
  return Buffer.from(hex, "hex").reverse().toString("hex");
}

/** Parse an 80-byte header given as 160 lowercase hex characters. The block hash is computed, never taken on trust. */
function parseHeader(hex) {
  if (typeof hex !== "string" || !HEADER_HEX.test(hex)) {
    throw chainError("MALFORMED_HEADER", "a block header must be 160 lowercase hex characters (80 bytes)");
  }
  const raw = Buffer.from(hex, "hex");
  const once = createHash("sha256").update(raw).digest();
  const hash = createHash("sha256").update(once).digest().reverse().toString("hex");
  return {
    hex,
    version: raw.readInt32LE(0),
    previousHash: reverseHex(hex.slice(8, 72)),
    merkleRoot: reverseHex(hex.slice(72, 136)),
    time: raw.readUInt32LE(68),
    bits: raw.readUInt32LE(72),
    nonce: raw.readUInt32LE(76),
    hash,
  };
}

/** Median of the timestamps of the given blocks (the last `span` of them must be supplied, oldest first). */
function medianOfTimes(times) {
  if (!Array.isArray(times) || times.length === 0 || times.some((time) => !Number.isSafeInteger(time))) {
    throw chainError("INVALID_TIMES", "timestamps must be a non-empty array of integers");
  }
  const sorted = [...times].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function assertHeight(height, label) {
  if (!Number.isSafeInteger(height) || height < 0) {
    throw chainError("INVALID_HEIGHT", `${label} must be a non-negative integer`);
  }
}

function parseAnchor(anchor, params) {
  if (!anchor || typeof anchor !== "object") throw chainError("INVALID_ANCHOR", "anchor is required");
  assertHeight(anchor.height, "anchor.height");
  const header = parseHeader(anchor.header);
  if (anchor.hash !== header.hash) {
    throw chainError("ANCHOR_HASH_MISMATCH", "anchor.hash is not the hash of anchor.header", { expected: header.hash });
  }
  const target = bitsToTarget(header.bits);
  if (target > params.powLimit) throw chainError("TARGET_ABOVE_LIMIT", "anchor target is above the network limit");
  if (BigInt(`0x${header.hash}`) > target) throw chainError("INSUFFICIENT_WORK", "anchor header does not meet its own target");
  if (target > params.minWorkTarget) {
    throw chainError("INSUFFICIENT_DIFFICULTY", "anchor difficulty is below the minimum accepted for mainnet");
  }
  return { height: anchor.height, hash: header.hash, target, time: header.time };
}

/**
 * Verify a run of consecutive headers.
 *
 * Checks, per header: format; proof of work against its own nBits; target within the network limit and
 * the absolute difficulty floor; link to the previous header; nBits unchanged except at a retarget
 * height, where the target may move by at most the retarget factor; timestamp above the median of the
 * previous eleven when those are present in the run.
 *
 * With an anchor (the chain tip committed to before the draw): the anchor header itself is verified; a
 * header's target may exceed the anchor's by at most the retarget factor per retarget boundary between
 * it and the anchor; and if the anchor height falls inside the run, the hashes must agree.
 *
 * @param {{height: number, hex: string}[]} headers ascending, consecutive heights
 * @returns parsed headers with `height`, `target` and `medianTime` (null where fewer than eleven are known)
 */
function verifyHeaderChain(headers, { params = BITCOIN_MAINNET, anchor = null } = {}) {
  if (!Array.isArray(headers) || headers.length === 0) {
    throw chainError("NO_HEADERS", "at least one header is required");
  }
  const anchorInfo = anchor ? parseAnchor(anchor, params) : null;
  const chain = [];
  for (let index = 0; index < headers.length; index += 1) {
    const item = headers[index];
    if (!item || typeof item !== "object") throw chainError("MALFORMED_HEADER", "header entries must be objects");
    assertHeight(item.height, "header height");
    const header = parseHeader(item.hex);
    const target = bitsToTarget(header.bits);
    const at = { height: item.height, hash: header.hash };

    if (target > params.powLimit) throw chainError("TARGET_ABOVE_LIMIT", `target above the network limit at height ${item.height}`, at);
    if (BigInt(`0x${header.hash}`) > target) throw chainError("INSUFFICIENT_WORK", `header at height ${item.height} does not meet its target`, at);
    if (target > params.minWorkTarget) {
      throw chainError("INSUFFICIENT_DIFFICULTY", `difficulty at height ${item.height} is below the minimum accepted for mainnet`, at);
    }

    const previous = chain[index - 1];
    if (previous) {
      if (item.height !== previous.height + 1) {
        throw chainError("NON_CONSECUTIVE_HEIGHTS", `height ${item.height} does not follow ${previous.height}`, at);
      }
      if (header.previousHash !== previous.hash) {
        throw chainError("BROKEN_LINK", `header at height ${item.height} does not link to the header before it`, at);
      }
      if (item.height % params.retargetInterval === 0) {
        if (target > previous.target * params.maxRetargetFactor || target * params.maxRetargetFactor < previous.target) {
          throw chainError("INVALID_RETARGET", `difficulty changed by more than the allowed factor at height ${item.height}`, at);
        }
      } else if (header.bits !== previous.bits) {
        throw chainError("UNEXPECTED_DIFFICULTY_CHANGE", `nBits changed outside a retarget boundary at height ${item.height}`, at);
      }
    }

    if (anchorInfo) {
      if (item.height === anchorInfo.height && header.hash !== anchorInfo.hash) {
        throw chainError("ANCHOR_MISMATCH", `header at the anchor height ${item.height} is not the anchor block`, at);
      }
      const period = (height) => Math.floor(height / params.retargetInterval);
      const boundaries = Math.abs(period(item.height) - period(anchorInfo.height));
      if (target > anchorInfo.target * params.maxRetargetFactor ** BigInt(boundaries)) {
        throw chainError("DIFFICULTY_BELOW_ANCHOR", `difficulty at height ${item.height} is too far below the anchor's`, at);
      }
    }

    let medianTime = null;
    if (index >= params.medianTimeSpan) {
      const previousMedian = medianOfTimes(chain.slice(index - params.medianTimeSpan, index).map((entry) => entry.time));
      if (header.time <= previousMedian) {
        throw chainError("TIME_TOO_OLD", `timestamp at height ${item.height} is not above the median of the previous blocks`, at);
      }
    }
    if (index >= params.medianTimeSpan - 1) {
      const window = chain.slice(index - (params.medianTimeSpan - 1), index).map((entry) => entry.time);
      medianTime = medianOfTimes([...window, header.time]);
    }

    chain.push({ ...header, height: item.height, target, medianTime });
  }
  return chain;
}

/**
 * Apply the rule `first-block-mtp-gte` to a verified run of headers.
 *
 * MTP(h) is the median of the header timestamps of blocks h-10 … h. The target block is the unique
 * height H with MTP(H) >= T and MTP(H-1) < T. It is usable once `confirmations` blocks exist from H
 * upward (H itself counts as the first), all of them present in the run.
 *
 * The function is stateless: call it again with the current headers and it re-decides from scratch, so
 * a reorganization before confirmation simply yields a different answer. It never accepts a block hash
 * or a height as input; the block comes out of the headers and the announced time only.
 *
 * @returns {{status: "confirmed", block, confirmations}
 *          | {status: "pending", reason: "target_time_not_reached" | "awaiting_confirmations", ...}}
 * @throws BitcoinVerificationError when the headers are invalid or cannot prove the rule
 */
function evaluateBlockRule({ headers, targetTimeUnix, confirmations, anchor = null, params = BITCOIN_MAINNET }) {
  if (!Number.isSafeInteger(targetTimeUnix) || targetTimeUnix <= 0) {
    throw chainError("INVALID_TARGET_TIME", "targetTimeUnix must be a positive integer (seconds)");
  }
  if (!Number.isSafeInteger(confirmations) || confirmations < 1) {
    throw chainError("INVALID_CONFIRMATIONS", "confirmations must be an integer of at least 1");
  }
  const chain = verifyHeaderChain(headers, { params, anchor });
  const firstWithMedian = chain.findIndex((entry) => entry.medianTime !== null);
  if (firstWithMedian === -1) {
    throw chainError("NOT_ENOUGH_HEADERS", `at least ${params.medianTimeSpan} consecutive headers are needed`);
  }
  if (chain[firstWithMedian].medianTime >= targetTimeUnix) {
    throw chainError(
      "WINDOW_STARTS_AFTER_TARGET",
      "the earliest median-time-past in the supplied headers is already at or after the target time; earlier headers are required",
    );
  }
  // Median-time-past is non-decreasing on a valid chain; the timestamp rule checked above guarantees it here.
  const index = chain.findIndex((entry) => entry.medianTime !== null && entry.medianTime >= targetTimeUnix);
  const tip = chain[chain.length - 1];
  if (index === -1) {
    return { status: "pending", reason: "target_time_not_reached", tipHeight: tip.height, tipMedianTime: tip.medianTime };
  }
  const block = chain[index];
  if (anchor && anchor.height >= block.height) {
    throw chainError(
      "ANCHOR_NOT_BEFORE_TARGET",
      "the anchor block is not below the target block, so the commitment cannot predate the target block",
      { anchorHeight: anchor.height, targetHeight: block.height },
    );
  }
  const seen = tip.height - block.height + 1;
  if (seen < confirmations) {
    return { status: "pending", reason: "awaiting_confirmations", candidateHeight: block.height, confirmations: seen, required: confirmations };
  }
  return {
    status: "confirmed",
    confirmations: seen,
    block: {
      height: block.height,
      hash: block.hash,
      time: block.time,
      medianTime: block.medianTime,
      previousMedianTime: chain[index - 1].medianTime,
    },
  };
}

/**
 * Combine header runs obtained from independent providers. Providers are untrusted transport: a height is
 * accepted only if at least `minSources` providers supplied it and every provider that did agrees byte for
 * byte. Any disagreement (a provider lagging behind a reorganization, or lying) yields no decision.
 */
function reconcileSources(sources, { minSources = 2 } = {}) {
  if (!Array.isArray(sources) || sources.length < minSources) {
    return { agreed: false, reason: "not_enough_sources", conflicts: [] };
  }
  const byHeight = new Map();
  for (const source of sources) {
    if (!source || typeof source.name !== "string" || !Array.isArray(source.headers)) {
      throw chainError("MALFORMED_SOURCE", "each source needs a name and a headers array");
    }
    const own = new Set();
    for (const item of source.headers) {
      assertHeight(item?.height, "header height");
      if (typeof item.hex !== "string" || !HEADER_HEX.test(item.hex)) {
        throw chainError("MALFORMED_HEADER", `source ${source.name} returned a malformed header at height ${item.height}`);
      }
      if (own.has(item.height)) {
        throw chainError("MALFORMED_SOURCE", `source ${source.name} returned height ${item.height} twice`);
      }
      own.add(item.height);
      const seen = byHeight.get(item.height) || [];
      seen.push({ source: source.name, hex: item.hex });
      byHeight.set(item.height, seen);
    }
  }
  const conflicts = [];
  const headers = [];
  for (const height of [...byHeight.keys()].sort((a, b) => a - b)) {
    const seen = byHeight.get(height);
    if (new Set(seen.map((entry) => entry.hex)).size > 1) {
      conflicts.push({ height, sources: seen.map((entry) => entry.source) });
    } else if (seen.length >= minSources) {
      headers.push({ height, hex: seen[0].hex });
    }
  }
  if (conflicts.length > 0) return { agreed: false, reason: "sources_disagree", conflicts };
  if (headers.length === 0) return { agreed: false, reason: "no_common_heights", conflicts: [] };
  for (let index = 1; index < headers.length; index += 1) {
    if (headers[index].height !== headers[index - 1].height + 1) {
      return { agreed: false, reason: "gap_in_common_heights", conflicts: [] };
    }
  }
  return { agreed: true, headers };
}

function isBlockHash(value) {
  return typeof value === "string" && BLOCK_HASH_HEX.test(value);
}

// ---- studentLottery.validation.js ----
/**
 * Student delegate lottery — mandate and eligibility validation.
 *
 * Pure: plain data in, plain data out. No database, no network, no imports.
 * Specification: docs/student-lottery/02-module-architecture-and-data-model.md §2 and
 * docs/student-lottery/04-lottery-correctness-and-verification.md §2.
 * This file is inlined into the published verify.mjs, so keep it dependency-free.
 */

const MANDATES_SCHEMA = "an-student-lottery/mandates/v1";
const STATUS_FILTERS = ["pending", "approved", "all"];

/** The congress allocation: nine groups, 100 mandates, 60 male and 40 female. */
const CONGRESS_MANDATE_RULES = Object.freeze({
  groupCount: 9,
  male: 60,
  female: 40,
});

const MANDATE_GENDERS = ["male", "female"];
const MANDATE_GROUP_CODE = /^[A-Z0-9_-]{1,32}$/;
const SCHOOL_ID = /^[a-f0-9]{24}$/;

/**
 * Same meaning as buildStudentFilter() in the registration service: records without a status are legacy
 * rows and count as pending, so "pending" means "not approved".
 */
function matchesStatusFilter(status, statusFilter) {
  if (statusFilter === "all") return true;
  if (statusFilter === "approved") return status === "approved";
  if (statusFilter === "pending") return status !== "approved";
  throw new TypeError(`Unknown status filter: ${statusFilter}`);
}

function isCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

/**
 * Validate a mandate table. `rules` are the expected totals; pass `null` to check structure only
 * (used for synthetic datasets). Returns every problem found, never throws on bad data.
 *
 * @returns {{ ok: boolean, errors: {code, message, group?}[], totals: {male, female, total} }}
 */
function validateMandates(mandates, rules = CONGRESS_MANDATE_RULES) {
  const errors = [];
  const totals = { male: 0, female: 0, total: 0 };
  const fail = (code, message, extra = {}) =>
    errors.push({ code, message, ...extra });

  if (
    !mandates ||
    typeof mandates !== "object" ||
    !Array.isArray(mandates.groups)
  ) {
    fail(
      "MANDATES_MALFORMED",
      "mandates must be an object with a groups array",
    );
    return { ok: false, errors, totals };
  }
  if (mandates.schema !== MANDATES_SCHEMA) {
    fail(
      "MANDATES_SCHEMA_MISMATCH",
      `mandates.schema must be ${MANDATES_SCHEMA}`,
    );
  }
  if (mandates.groups.length === 0)
    fail("MANDATES_MALFORMED", "mandates.groups is empty");

  const codes = new Set();
  const orders = new Set();
  const schools = new Map();
  for (const group of mandates.groups) {
    const code = typeof group?.code === "string" ? group.code : "";
    if (!MANDATE_GROUP_CODE.test(code)) {
      fail("MANDATE_GROUP_INVALID", "group code must match [A-Z0-9_-]{1,32}", {
        group: code,
      });
      continue;
    }
    if (codes.has(code))
      fail("MANDATE_GROUP_DUPLICATE", `group ${code} is listed twice`, {
        group: code,
      });
    codes.add(code);
    if (typeof group.name !== "string" || group.name.trim() === "") {
      fail("MANDATE_GROUP_INVALID", `group ${code} has no name`, {
        group: code,
      });
    }
    if (!Number.isSafeInteger(group.order) || group.order < 1) {
      fail(
        "MANDATE_GROUP_INVALID",
        `group ${code} needs a positive integer order`,
        { group: code },
      );
    } else if (orders.has(group.order)) {
      fail("MANDATE_ORDER_DUPLICATE", `order ${group.order} is used twice`, {
        group: code,
      });
    } else {
      orders.add(group.order);
    }
    for (const gender of MANDATE_GENDERS) {
      const quota = group.quota?.[gender];
      if (!isCount(quota)) {
        fail(
          "MANDATE_QUOTA_INVALID",
          `group ${code} needs a non-negative integer ${gender} quota`,
          { group: code, gender },
        );
      } else {
        totals[gender] += quota;
      }
    }
    if (!Array.isArray(group.schools) || group.schools.length === 0) {
      fail("MANDATE_SCHOOLS_MISSING", `group ${code} lists no schools`, {
        group: code,
      });
      continue;
    }
    for (const school of group.schools) {
      const id = typeof school?.id === "string" ? school.id : "";
      if (!SCHOOL_ID.test(id)) {
        fail(
          "MANDATE_SCHOOL_INVALID",
          `group ${code} has a school without a valid id`,
          { group: code },
        );
        continue;
      }
      if (typeof school.name !== "string" || school.name.trim() === "") {
        fail(
          "MANDATE_SCHOOL_INVALID",
          `school ${id} in group ${code} has no name`,
          { group: code, schoolId: id },
        );
      }
      if (schools.has(id)) {
        fail(
          "MANDATE_SCHOOL_DUPLICATE",
          `school ${id} is mapped to ${schools.get(id)} and ${code}`,
          { group: code, schoolId: id },
        );
      } else {
        schools.set(id, code);
      }
    }
  }
  totals.total = totals.male + totals.female;

  if (mandates.totals !== undefined) {
    if (
      mandates.totals?.male !== totals.male ||
      mandates.totals?.female !== totals.female
    ) {
      fail(
        "MANDATE_TOTAL_MISMATCH",
        "mandates.totals does not equal the sum of the group quotas",
      );
    }
  }
  if (rules) {
    if (mandates.groups.length !== rules.groupCount) {
      fail(
        "MANDATE_GROUP_COUNT_MISMATCH",
        `expected ${rules.groupCount} mandate groups, found ${mandates.groups.length}`,
      );
    }
    if (totals.male !== rules.male || totals.female !== rules.female) {
      fail(
        "MANDATE_TOTAL_MISMATCH",
        `expected ${rules.male} male and ${rules.female} female mandates, found ${totals.male} and ${totals.female}`,
      );
    }
  }
  return { ok: errors.length === 0, errors, totals };
}

/** Map of school id → group code. Call only with a mandate table that passed validateMandates(). */
function schoolGroupIndex(mandates) {
  const index = new Map();
  for (const group of mandates.groups) {
    for (const school of group.schools) index.set(school.id, group.code);
  }
  return index;
}

/**
 * Expected outcome of one pool under the partial policy. Same arithmetic as poolPlan() in the algorithm
 * module (this file may not import it); a test keeps the two equal.
 */
function plannedPool(available, quota) {
  return {
    selected: Math.min(available, quota),
    vacant: Math.max(0, quota - available),
    reserve: Math.max(0, available - quota),
    method: available > quota && quota > 0 ? "random" : "automatic",
  };
}

/**
 * Decide who is eligible and whether the draw may run (the preflight).
 *
 * `candidates` are plain objects `{ id, schoolId, status, gender }`. `gender` is the caller's result of
 * genderFromRegisterNumber(): "male", "female", or null when the register number is malformed.
 *
 * `policy` is the quota policy of the lottery's algorithm version:
 *   "strict"  (v1) a pool with fewer eligible entries than mandates is an error (QUOTA_UNFILLED).
 *   "partial" (v2) such a pool is a warning: everyone in it is selected and the rest of its mandates stay
 *             vacant (QUOTA_PARTIAL, or QUOTA_EMPTY when nobody is eligible). Only genuine integrity
 *             problems, or no eligible entry at all, are errors.
 * Any error makes `ok` false and the draw must not run. A short pool is never topped up from another
 * pool, and no mandate is carried over.
 *
 * @returns {{
 *   ok: boolean, statusFilter: string,
 *   errors: object[], warnings: object[],
 *   totals: { eligible: number, male: number, female: number },
 *   groups: { code, name, order, male: {quota, eligible, ok}, female: {quota, eligible, ok} }[],
 *   eligible: { id: string, group: string, gender: string, schoolId: string }[]   // empty unless ok
 * }}
 */
function evaluateEligibility({
  candidates,
  mandates,
  statusFilter,
  rules = CONGRESS_MANDATE_RULES,
  policy = "strict",
}) {
  const errors = [];
  if (policy !== "strict" && policy !== "partial")
    throw new TypeError(`Unknown quota policy: ${policy}`);
  const warnings = [];
  const empty = {
    ok: false,
    statusFilter,
    errors,
    warnings,
    totals: { eligible: 0, male: 0, female: 0 },
    groups: [],
    eligible: [],
  };

  if (!STATUS_FILTERS.includes(statusFilter)) {
    errors.push({
      code: "INVALID_STATUS_FILTER",
      message: "status filter must be pending, approved or all",
    });
  }
  const mandateCheck = validateMandates(mandates, rules);
  errors.push(...mandateCheck.errors);
  if (!Array.isArray(candidates)) {
    errors.push({
      code: "CANDIDATES_MALFORMED",
      message: "candidates must be an array",
    });
  }
  if (errors.length > 0) return empty;

  const groupOf = schoolGroupIndex(mandates);
  const counts = new Map(
    mandates.groups.map((group) => [group.code, { male: 0, female: 0 }]),
  );
  const seen = new Set();
  const eligible = [];
  const unmapped = new Map();

  for (const candidate of candidates) {
    const id = typeof candidate?.id === "string" ? candidate.id : "";
    if (id === "") {
      errors.push({
        code: "PARTICIPANT_ID_MISSING",
        message: "a candidate has no identifier",
      });
      continue;
    }
    // Duplicates are rejected across the whole input, before filtering, so a person can never be listed twice.
    if (seen.has(id)) {
      errors.push({
        code: "DUPLICATE_PARTICIPANT",
        message: `participant ${id} appears more than once`,
        id,
      });
      continue;
    }
    seen.add(id);
    if (!matchesStatusFilter(candidate.status, statusFilter)) continue;

    if (!MANDATE_GENDERS.includes(candidate.gender)) {
      errors.push({
        code: "INVALID_GENDER",
        message: `participant ${id} has no valid gender (malformed register number)`,
        id,
      });
      continue;
    }
    const schoolId =
      typeof candidate.schoolId === "string"
        ? candidate.schoolId
        : String(candidate.schoolId ?? "");
    const group = groupOf.get(schoolId);
    if (!group) {
      unmapped.set(schoolId, (unmapped.get(schoolId) || 0) + 1);
      continue;
    }
    counts.get(group)[candidate.gender] += 1;
    eligible.push({ id, group, gender: candidate.gender, schoolId });
  }

  for (const [schoolId, count] of unmapped) {
    errors.push({
      code: "UNMAPPED_SCHOOL",
      message: `${count} eligible registration(s) belong to school ${schoolId || "(missing)"}, which is in no mandate group`,
      schoolId,
      count,
    });
  }

  const planned = {
    allocated: { male: 0, female: 0, total: 0 },
    selected: { male: 0, female: 0, total: 0 },
    vacant: { male: 0, female: 0, total: 0 },
    reserve: { male: 0, female: 0, total: 0 },
  };
  const groups = [...mandates.groups]
    .sort((a, b) => a.order - b.order)
    .map((group) => {
      const row = { code: group.code, name: group.name, order: group.order };
      for (const gender of MANDATE_GENDERS) {
        const quota = group.quota[gender];
        const available = counts.get(group.code)[gender];
        const plan = plannedPool(available, quota);
        // `eligible` and `ok` (pool full) keep their v1 meaning; under "partial" the row also describes the
        // expected draw. A strict (v1) row keeps exactly its original shape.
        row[gender] =
          policy === "partial"
            ? {
                quota,
                eligible: available,
                ok: available >= quota,
                available,
                ...plan,
              }
            : { quota, eligible: available, ok: available >= quota };
        for (const [key, value] of [
          ["allocated", quota],
          ["selected", plan.selected],
          ["vacant", plan.vacant],
          ["reserve", plan.reserve],
        ]) {
          planned[key][gender] += value;
          planned[key].total += value;
        }
        if (available < quota && policy === "partial") {
          warnings.push({
            code: available === 0 ? "QUOTA_EMPTY" : "QUOTA_PARTIAL",
            message:
              available === 0
                ? `${group.code}/${gender}: no eligible registration; all ${quota} mandate(s) stay vacant`
                : `${group.code}/${gender}: ${available} eligible for ${quota} mandates; all ${available} are selected automatically and ${quota - available} stay vacant`,
            group: group.code,
            gender,
            quota,
            eligible: available,
            vacant: quota - available,
          });
        } else if (available < quota) {
          errors.push({
            code: "QUOTA_UNFILLED",
            message: `${group.code}/${gender}: ${available} eligible for ${quota} mandates`,
            group: group.code,
            gender,
            quota,
            eligible: available,
            missing: quota - available,
          });
        } else if (available === quota && quota > 0) {
          warnings.push({
            code: "NO_RESERVE",
            message: `${group.code}/${gender}: everyone eligible is selected`,
            group: group.code,
            gender,
          });
        }
      }
      if (policy === "partial") {
        row.selected = row.male.selected + row.female.selected;
        row.vacant = row.male.vacant + row.female.vacant;
      }
      return row;
    });

  if (policy === "partial" && errors.length === 0 && eligible.length === 0) {
    errors.push({
      code: "NO_ELIGIBLE_ENTRIES",
      message:
        "no registration is eligible under this status filter; there is nothing to draw",
    });
  }

  const ok = errors.length === 0;
  return {
    ok,
    statusFilter,
    errors,
    warnings,
    totals: {
      eligible: eligible.length,
      male: eligible.filter((entry) => entry.gender === "male").length,
      female: eligible.filter((entry) => entry.gender === "female").length,
    },
    ...(policy === "partial" ? { policy, planned } : {}),
    groups,
    eligible: ok ? eligible : [],
  };
}

// ---- studentLottery.onDemand.js ----
/**
 * Student delegate lottery — on-demand block selection (block rule `on-demand-random-day-block/v1`).
 *
 * The scheduled rule (`first-block-mtp-gte`) commits to a FUTURE block that nobody can choose. This rule
 * is for draws that should happen on the day, without waiting for a pre-announced time:
 *
 *   1. At the lock the server draws a 32-byte secret with a CSPRNG and commits to SHA-256(secret) inside
 *      commitment.json, which is published before any selection.
 *   2. At the draw the candidate set is frozen: every Bitcoin mainnet block whose median-time-past falls on
 *      the lottery's calendar day in Asia/Ulaanbaatar (UTC+8, no daylight saving), that was mined after the
 *      lock's anchor block, and that has the committed number of confirmations in the headers obtained
 *      from two independent explorers. Ordered by height; a height appears once.
 *   3. The block index is derived from the revealed secret and the hash of the frozen candidate list by
 *      unbiased rejection sampling over HMAC-SHA256 output: index = uniform in [0, n).
 *   4. The selected block hash feeds the existing deterministic delegate ranking (algorithm v1/v2 unchanged).
 *
 * What a verifier can check: the secret matches the published commitment; the candidate list is exactly
 * what the rule gives on the published headers (proof of work, linkage, anchor, window, confirmations);
 * the index follows from the secret and the list; the delegates follow from the block hash.
 *
 * What it cannot check (stated in every report): the server knew the secret, and chose when to freeze the
 * candidate set (each newly confirmed block changes the set and therefore the index). A dishonest server
 * could compute outcomes for several freeze moments and draw at a convenient one, or withhold a result.
 * Excluding blocks mined before the lock stops the outcome being known when the list is locked, but this
 * is NOT equivalent to the future-block rule. See docs/student-lottery/04 §11.
 *
 * Pure: no network, no database, no clock. Inlined into the published verify.mjs; names are prefixed
 * to stay unique in the joined file.
 */

const ON_DEMAND_RULE_TYPE = "on-demand-random-day-block/v1";
const ON_DEMAND_SELECTION_METHOD = "hmac-sha256-rejection-sampling/v1";
const LOTTERY_TIME_ZONE = "Asia/Ulaanbaatar";
/** Asia/Ulaanbaatar has been UTC+8 without daylight saving since 2017. */
const LOTTERY_UTC_OFFSET_SECONDS = 8 * 3600;
/** Explorers return at most a few hundred headers per request; a day has about 144 blocks. */
const ON_DEMAND_MAX_HEADERS = 400;

const OD_DAY = /^(\d{4})-(\d{2})-(\d{2})$/;
const OD_HEX_32 = /^[0-9a-f]{64}$/;
const odError = (code, message, details) => new BitcoinVerificationError(code, message, details);
const odSha256 = (value) => createHash("sha256").update(value).digest("hex");
const odIso = (unix) => `${new Date(unix * 1000).toISOString().slice(0, 19)}Z`;

/** The lottery day as a half-open UTC window [start, end). Throws on a malformed or impossible date. */
function dayWindow(day) {
  const match = typeof day === "string" ? OD_DAY.exec(day) : null;
  if (!match) throw odError("INVALID_DAY", "the lottery day must be YYYY-MM-DD");
  const [year, month, date] = match.slice(1).map(Number);
  const midnightUtc = Date.UTC(year, month - 1, date) / 1000;
  if (odIso(midnightUtc).slice(0, 10) !== day) throw odError("INVALID_DAY", `${day} is not a calendar date`);
  const startUnix = midnightUtc - LOTTERY_UTC_OFFSET_SECONDS;
  const endUnix = startUnix + 24 * 3600;
  return { day, timeZone: LOTTERY_TIME_ZONE, startUnix, endUnix, start: odIso(startUnix), end: odIso(endUnix) };
}

/** Calendar day in Asia/Ulaanbaatar of a Unix time (seconds). */
function lotteryDayOf(unixSeconds) {
  return odIso(unixSeconds + LOTTERY_UTC_OFFSET_SECONDS).slice(0, 10);
}

/** The value published at the lock: SHA-256 of the 32 secret bytes, hex. */
function selectionSecretCommitment(secretHex) {
  if (typeof secretHex !== "string" || !OD_HEX_32.test(secretHex)) throw odError("INVALID_SECRET", "the selection secret must be 32 bytes as lowercase hex");
  return odSha256(Buffer.from(secretHex, "hex"));
}

/** SHA-256 over "height:hash\n" lines in list order: identifies the frozen candidate list exactly. */
function candidateListSha256(candidates) {
  return odSha256(Buffer.from(candidates.map((candidate) => `${candidate.height}:${candidate.hash}\n`).join(""), "utf8"));
}

/**
 * Uniform index in [0, count) from the secret and the frozen list. Each round takes the first four bytes of
 * HMAC-SHA256(secret, "an-student-lottery/on-demand/v1/index\n" + listSha256 + "\n" + round) as an
 * unsigned 32-bit integer and accepts it only below the largest multiple of `count` (no modulo bias).
 */
function selectCandidateIndex(secretHex, listSha256, count) {
  selectionSecretCommitment(secretHex);
  if (!Number.isSafeInteger(count) || count < 1 || count > 2 ** 32) throw odError("INVALID_CANDIDATE_COUNT", "there must be at least one candidate");
  if (typeof listSha256 !== "string" || !OD_HEX_32.test(listSha256)) throw odError("INVALID_CANDIDATE_LIST_HASH", "the candidate list hash is malformed");
  const limit = 2 ** 32 - (2 ** 32 % count);
  for (let round = 0; round < 1024; round += 1) {
    const digest = createHmac("sha256", Buffer.from(secretHex, "hex"))
      .update(`an-student-lottery/on-demand/v1/index\n${listSha256}\n${round}`, "utf8").digest();
    const value = digest.readUInt32BE(0);
    if (value < limit) return { index: value % count, rounds: round + 1 };
  }
  // Unreachable in practice: each round is accepted with probability above one half.
  throw odError("INDEX_NOT_FOUND", "no acceptable value in 1024 rounds");
}

/**
 * Apply the candidate rule to a run of headers obtained from the explorers.
 *
 * Candidates: heights h in the run with median-time-past(h) in [window.startUnix, window.endUnix),
 * h > anchor.height, and h + confirmations - 1 <= the last height of the run (the confirmations are in the
 * run itself). The run must start early enough to show that nothing before the first candidate qualifies:
 * its first header with a known median time must be at or below the anchor, or have a median time before
 * the window. The last header of the run is the frozen tip.
 *
 * @returns {{ candidates: {height, hash, time, medianTime}[], frozenTipHeight: number, chain }}
 */
function evaluateDayCandidates({ headers, window, confirmations, anchor, params = BITCOIN_MAINNET }) {
  if (!Number.isSafeInteger(confirmations) || confirmations < 1) throw odError("INVALID_CONFIRMATIONS", "confirmations must be an integer of at least 1");
  if (!anchor || !Number.isSafeInteger(anchor.height)) throw odError("ANCHOR_REQUIRED", "the commitment's anchor block is required");
  if (!Array.isArray(headers) || headers.length > ON_DEMAND_MAX_HEADERS) throw odError("TOO_MANY_HEADERS", `at most ${ON_DEMAND_MAX_HEADERS} headers`);
  const chain = verifyHeaderChain(headers, { params, anchor });
  const firstKnown = chain.find((entry) => entry.medianTime !== null);
  if (!firstKnown) throw odError("NOT_ENOUGH_HEADERS", `at least ${params.medianTimeSpan} consecutive headers are needed`);
  if (!(firstKnown.height <= anchor.height || firstKnown.medianTime < window.startUnix)) {
    throw odError("CANDIDATE_START_NOT_COVERED", "the headers do not reach back far enough to show where the candidate range begins");
  }
  const frozenTipHeight = chain[chain.length - 1].height;
  const candidates = chain
    .filter((entry) => entry.medianTime !== null && entry.medianTime >= window.startUnix && entry.medianTime < window.endUnix
      && entry.height > anchor.height && entry.height + confirmations - 1 <= frozenTipHeight)
    .map((entry) => ({ height: entry.height, hash: entry.hash, time: entry.time, medianTime: entry.medianTime }));
  return { candidates, frozenTipHeight, chain };
}

// ---- studentLottery.documents.js ----
/**
 * Student delegate lottery — published document formats and their hashes.
 *
 * Pure: no database, no network, no clock. Every time value is passed in by the caller.
 * Specification: docs/student-lottery/04-lottery-correctness-and-verification.md §2, §3, §6.
 * This file is inlined into the published verify.mjs, so keep it dependency-free apart from node:crypto
 * and the sibling pure modules.
 */

const SNAPSHOT_SCHEMA = "an-student-lottery/snapshot/v1";
const COMMITMENT_SCHEMA = "an-student-lottery/commitment/v1";
const PROOF_SCHEMA = "an-student-lottery/proof/v1";
/** proof.json of an on-demand lottery: frozen candidate blocks, the revealed secret and the selected block. */
const ON_DEMAND_PROOF_SCHEMA = "an-student-lottery/proof-on-demand/v1";
const RESULTS_SCHEMA = "an-student-lottery/results/v1";
/** results.json of a v2 (partial fulfilment) lottery: adds availability, vacancies and the selection method. */
const RESULTS_SCHEMA_V2 = "an-student-lottery/results/v2";
/** The results schema that belongs to an algorithm version. */
const resultsSchemaFor = (algorithm) => (assertSupportedAlgorithm(algorithm) === ALGORITHM_V1 ? RESULTS_SCHEMA : RESULTS_SCHEMA_V2);

/** The commitment must be public at least this long before the target time (see document 04 §4). */
const COMMIT_LEAD_SECONDS = 3 * 60 * 60;

const SHA256_HEX = /^[0-9a-f]{64}$/;
const SNAPSHOT_ENTRY_ID = /^[0-9a-f]{32}$/;
const PUBLIC_ID = /^[a-z0-9-]{3,60}$/;
const ISO_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

class LotteryDocumentError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "LotteryDocumentError";
    this.code = code;
  }
}

function documentError(code, message) {
  return new LotteryDocumentError(code, message);
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizeStrings(value) {
  if (typeof value === "string") return value.normalize("NFC");
  if (Array.isArray(value)) return value.map(normalizeStrings);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key.normalize("NFC"), normalizeStrings(item)]));
  }
  return value;
}

/**
 * The one serialization used for every published JSON file: UTF-8, strings in NFC, two-space indent,
 * "\n" line endings, one trailing newline. Hashes are taken over these bytes, so a verifier never has
 * to re-serialize anything. Key order is the order in which the builders below create the keys.
 */
function serializeDocument(document) {
  return Buffer.from(`${JSON.stringify(normalizeStrings(document), null, 2)}\n`, "utf8");
}

/** UTC timestamp with second precision, e.g. 2026-11-13T12:00:00Z. */
function toIsoSeconds(unixSeconds) {
  if (!Number.isSafeInteger(unixSeconds)) throw documentError("INVALID_TIME", "time must be an integer number of seconds");
  return `${new Date(unixSeconds * 1000).toISOString().slice(0, 19)}Z`;
}

function fromIsoSeconds(text) {
  if (typeof text !== "string" || !ISO_SECONDS.test(text)) return null;
  const millis = Date.parse(text);
  return Number.isNaN(millis) ? null : millis / 1000;
}

/** identityCommitment = SHA-256(salt bytes ‖ UTF-8 register number), hex. The salt stays private. */
function identityCommitment(saltHex, registerNumber) {
  if (typeof saltHex !== "string" || !SHA256_HEX.test(saltHex)) {
    throw documentError("INVALID_SALT", "identity salt must be 32 bytes as lowercase hex");
  }
  if (typeof registerNumber !== "string" || registerNumber === "") {
    throw documentError("INVALID_REGISTER_NUMBER", "register number is required");
  }
  return createHash("sha256").update(Buffer.from(saltHex, "hex")).update(registerNumber.normalize("NFC"), "utf8").digest("hex");
}

function buildMandatesDocument(groups) {
  const ordered = [...groups].sort((a, b) => a.order - b.order);
  const totals = { male: 0, female: 0 };
  for (const group of ordered) {
    totals.male += group.quota.male;
    totals.female += group.quota.female;
  }
  return {
    schema: MANDATES_SCHEMA,
    totals,
    groups: ordered.map((group) => ({
      order: group.order,
      code: group.code,
      name: group.name,
      quota: { male: group.quota.male, female: group.quota.female },
      schools: group.schools.map((school) => ({ id: school.id, name: school.name })),
    })),
  };
}

/**
 * Entries are placed in the canonical order (group order, male before female, entryId ascending) and
 * numbered from 1. The input order, e.g. MongoDB's, has no influence.
 */
function buildSnapshotDocument({ lotteryId, statusFilter, mandates, entries }) {
  const groupOrder = new Map(mandates.groups.map((group) => [group.code, group.order]));
  const sorted = [...entries].sort((a, b) => {
    const byGroup = groupOrder.get(a.group) - groupOrder.get(b.group);
    if (byGroup !== 0) return byGroup;
    const byGender = LOTTERY_GENDERS.indexOf(a.gender) - LOTTERY_GENDERS.indexOf(b.gender);
    if (byGender !== 0) return byGender;
    return a.entryId < b.entryId ? -1 : a.entryId > b.entryId ? 1 : 0;
  });
  return {
    schema: SNAPSHOT_SCHEMA,
    lotteryId,
    statusFilter,
    entryCount: sorted.length,
    entries: sorted.map((entry, index) => ({
      seq: index + 1,
      entryId: entry.entryId,
      group: entry.group,
      gender: entry.gender,
      school: entry.school,
      name: entry.name,
      identityCommitment: entry.identityCommitment,
    })),
  };
}

/** Structural check of a parsed snapshot against a parsed mandate table. Returns a list of problems. */
function validateSnapshotDocument(snapshot, mandates) {
  const problems = [];
  if (!snapshot || typeof snapshot !== "object" || !Array.isArray(snapshot.entries)) {
    return ["snapshot must be an object with an entries array"];
  }
  if (snapshot.schema !== SNAPSHOT_SCHEMA) problems.push(`snapshot.schema must be ${SNAPSHOT_SCHEMA}`);
  if (typeof snapshot.lotteryId !== "string" || !PUBLIC_ID.test(snapshot.lotteryId)) problems.push("snapshot.lotteryId is invalid");
  if (!STATUS_FILTERS.includes(snapshot.statusFilter)) problems.push("snapshot.statusFilter must be pending, approved or all");
  if (snapshot.entryCount !== snapshot.entries.length) {
    problems.push(`snapshot.entryCount is ${snapshot.entryCount} but there are ${snapshot.entries.length} entries`);
  }
  const groups = new Set((mandates?.groups || []).map((group) => group.code));
  const ids = new Set();
  snapshot.entries.forEach((entry, index) => {
    const label = `entry #${index + 1}`;
    if (entry?.seq !== index + 1) problems.push(`${label}: seq must be ${index + 1}`);
    if (typeof entry?.entryId !== "string" || !SNAPSHOT_ENTRY_ID.test(entry.entryId)) {
      problems.push(`${label}: entryId must be 32 lowercase hex characters`);
    } else if (ids.has(entry.entryId)) {
      problems.push(`${label}: entryId ${entry.entryId} is duplicated`);
    } else {
      ids.add(entry.entryId);
    }
    if (!groups.has(entry?.group)) problems.push(`${label}: group ${entry?.group} is not in the mandate table`);
    if (!LOTTERY_GENDERS.includes(entry?.gender)) problems.push(`${label}: gender must be male or female`);
    if (typeof entry?.identityCommitment !== "string" || !SHA256_HEX.test(entry.identityCommitment)) {
      problems.push(`${label}: identityCommitment must be a SHA-256 hex value`);
    }
  });
  return problems.slice(0, 20);
}

/**
 * @param anchor `{ height, header }` — the chain tip observed at lock time, as an 80-byte header in hex.
 *        Its hash is computed here; it is evidence that the commitment did not exist before that block.
 */
function buildCommitmentDocument({
  lotteryId, title, statusFilter, mandatesBytes, snapshotBytes, entryCount,
  targetTimeUnix, confirmations, anchor, lockedAtUnix, algorithm = ALGORITHM_V1, onDemand = null,
}) {
  if (onDemand) {
    return buildOnDemandCommitment({
      lotteryId, title, statusFilter, mandatesBytes, snapshotBytes, entryCount, confirmations, anchor, lockedAtUnix, algorithm, onDemand,
    });
  }
  try {
    assertSupportedAlgorithm(algorithm);
  } catch {
    throw documentError("UNSUPPORTED_ALGORITHM", `algorithm ${algorithm} is not supported`);
  }
  if (typeof lotteryId !== "string" || !PUBLIC_ID.test(lotteryId)) throw documentError("INVALID_LOTTERY_ID", "lotteryId is invalid");
  if (!STATUS_FILTERS.includes(statusFilter)) throw documentError("INVALID_STATUS_FILTER", "statusFilter is invalid");
  if (!Number.isSafeInteger(confirmations) || confirmations < 1) throw documentError("INVALID_CONFIRMATIONS", "confirmations must be at least 1");
  if (!Number.isSafeInteger(targetTimeUnix) || !Number.isSafeInteger(lockedAtUnix)) throw documentError("INVALID_TIME", "times must be integer seconds");
  if (targetTimeUnix - lockedAtUnix < COMMIT_LEAD_SECONDS) {
    throw documentError("TARGET_TIME_TOO_SOON", "the target time must be at least three hours after the lock");
  }
  if (!Number.isSafeInteger(anchor?.height) || anchor.height < 0) throw documentError("INVALID_ANCHOR", "anchor.height is invalid");
  const anchorHeader = parseHeader(anchor.header);
  return {
    schema: COMMITMENT_SCHEMA,
    lotteryId,
    title,
    algorithm,
    statusFilter,
    entryCount,
    snapshotSha256: sha256Hex(snapshotBytes),
    mandatesSha256: sha256Hex(mandatesBytes),
    blockRule: {
      network: BITCOIN_NETWORK,
      type: BLOCK_RULE_TYPE,
      targetTime: toIsoSeconds(targetTimeUnix),
      targetTimeUnix,
      confirmations,
    },
    anchor: { height: anchor.height, hash: anchorHeader.hash, header: anchor.header },
    lockedAt: toIsoSeconds(lockedAtUnix),
  };
}

/**
 * `ruleResult` is the "confirmed" value returned by evaluateBlockRule(); `headers` are the ones it was
 * given. The block hash therefore always comes out of verified headers, never from a caller.
 */
function buildProofDocument({ lotteryId, commitmentSha256, ruleResult, headers, sources, resolvedAtUnix }) {
  if (ruleResult?.status !== "confirmed") throw documentError("BLOCK_NOT_CONFIRMED", "a proof needs a confirmed block rule result");
  const { block } = ruleResult;
  const first = block.height - 11;
  const last = block.height + ruleResult.confirmations - 1;
  const window = headers.filter((header) => header.height >= first && header.height <= last);
  return {
    schema: PROOF_SCHEMA,
    lotteryId,
    commitmentSha256,
    block: {
      height: block.height,
      hash: block.hash,
      time: block.time,
      medianTime: block.medianTime,
      previousMedianTime: block.previousMedianTime,
    },
    headers: window.map((header) => ({ height: header.height, hex: header.hex })),
    tipHeightAtResolve: last,
    sources: [...sources],
    resolvedAt: toIsoSeconds(resolvedAtUnix),
    seed: deriveSeed(commitmentSha256, block.hash).toString("hex"),
  };
}

/**
 * Run the draw from parsed documents and a verified block hash, and shape it as results.json.
 * `algorithm` is the committed version (commitment.algorithm). A v1 document is byte-for-byte what v1
 * always produced; a v2 document adds, per pool, how many were available, the method and the vacancies,
 * and the totals.
 */
function buildResultsDocument({ mandates, snapshot, commitmentSha256, blockHash, selectedNames = {}, algorithm = ALGORITHM_V1 }) {
  const seed = deriveSeed(commitmentSha256, blockHash);
  const outcome = draw({ groups: mandates.groups, entries: snapshot.entries, seed, algorithm });
  if (algorithm !== ALGORITHM_V1) return resultsV2({ outcome, snapshot, algorithm, commitmentSha256, blockHash, seed, selectedNames });
  return {
    schema: RESULTS_SCHEMA,
    lotteryId: snapshot.lotteryId,
    algorithm: ALGORITHM_V1,
    commitmentSha256,
    blockHash,
    seed: seed.toString("hex"),
    groups: outcome.map((group) => {
      const row = { code: group.code };
      for (const pool of group.pools) {
        row[pool.gender] = {
          quota: pool.quota,
          selected: pool.selected.map((item) => ({
            rank: item.rank,
            entryId: item.entryId,
            ticket: item.ticket,
            ...(typeof selectedNames[item.entryId] === "string" ? { name: selectedNames[item.entryId] } : {}),
          })),
          reserve: pool.reserve.map((item) => ({ rank: item.rank, entryId: item.entryId, ticket: item.ticket })),
        };
      }
      return row;
    }),
  };
}

const ranked = (item) => ({ rank: item.rank, entryId: item.entryId, ticket: item.ticket });

function resultsV2({ outcome, snapshot, algorithm, commitmentSha256, blockHash, seed, selectedNames }) {
  const totals = {
    allocated: { male: 0, female: 0, total: 0 }, selected: { male: 0, female: 0, total: 0 },
    vacant: { male: 0, female: 0, total: 0 }, reserve: { male: 0, female: 0, total: 0 },
  };
  const groups = outcome.map((group) => {
    const row = { code: group.code };
    for (const pool of group.pools) {
      for (const [key, value] of [["allocated", pool.quota], ["selected", pool.selected.length], ["vacant", pool.vacant], ["reserve", pool.reserve.length]]) {
        totals[key][pool.gender] += value;
        totals[key].total += value;
      }
      row[pool.gender] = {
        quota: pool.quota,
        available: pool.available,
        method: pool.method,
        vacant: pool.vacant,
        selected: pool.selected.map((item) => ({
          ...ranked(item),
          ...(typeof selectedNames[item.entryId] === "string" ? { name: selectedNames[item.entryId] } : {}),
        })),
        reserve: pool.reserve.map(ranked),
      };
    }
    return row;
  });
  return {
    schema: RESULTS_SCHEMA_V2,
    lotteryId: snapshot.lotteryId,
    algorithm,
    commitmentSha256,
    blockHash,
    seed: seed.toString("hex"),
    totals,
    groups,
  };
}

/**
 * commitment.json of an on-demand lottery. Same fields as the scheduled form except `blockRule`, which
 * states the day window, the candidate rule and the commitment to the selection secret. The secret itself
 * stays private until the draw. `onDemand` = { day, secretHex }.
 */
function buildOnDemandCommitment({
  lotteryId, title, statusFilter, mandatesBytes, snapshotBytes, entryCount, confirmations, anchor, lockedAtUnix, algorithm, onDemand,
}) {
  if (typeof lotteryId !== "string" || !PUBLIC_ID.test(lotteryId)) throw documentError("INVALID_LOTTERY_ID", "lotteryId is invalid");
  if (!STATUS_FILTERS.includes(statusFilter)) throw documentError("INVALID_STATUS_FILTER", "statusFilter is invalid");
  if (!Number.isSafeInteger(confirmations) || confirmations < 1) throw documentError("INVALID_CONFIRMATIONS", "confirmations must be at least 1");
  if (!Number.isSafeInteger(lockedAtUnix)) throw documentError("INVALID_TIME", "times must be integer seconds");
  assertSupportedAlgorithm(algorithm);
  const window = dayWindow(onDemand.day);
  if (lockedAtUnix >= window.endUnix) throw documentError("LOTTERY_DAY_OVER", "the lottery day has already ended");
  if (!Number.isSafeInteger(anchor?.height) || anchor.height < 0) throw documentError("INVALID_ANCHOR", "anchor.height is invalid");
  const anchorHeader = parseHeader(anchor.header);
  return {
    schema: COMMITMENT_SCHEMA,
    lotteryId,
    title,
    algorithm,
    statusFilter,
    entryCount,
    snapshotSha256: sha256Hex(snapshotBytes),
    mandatesSha256: sha256Hex(mandatesBytes),
    blockRule: {
      network: BITCOIN_NETWORK,
      type: ON_DEMAND_RULE_TYPE,
      day: window.day,
      timeZone: LOTTERY_TIME_ZONE,
      windowStart: window.start,
      windowStartUnix: window.startUnix,
      windowEnd: window.end,
      windowEndUnix: window.endUnix,
      timestamp: "median-time-past",
      minedAfterAnchor: true,
      confirmations,
      selection: { method: ON_DEMAND_SELECTION_METHOD, secretSha256: selectionSecretCommitment(onDemand.secretHex) },
    },
    anchor: { height: anchor.height, hash: anchorHeader.hash, header: anchor.header },
    lockedAt: toIsoSeconds(lockedAtUnix),
  };
}

/**
 * proof.json of an on-demand lottery. `evaluated` is the result of evaluateDayCandidates() on `headers`;
 * the index and the block come out of the secret and the frozen list, never from a caller.
 * `explorers` records, per source, the hash each explorer reported for the selected height.
 */
function buildOnDemandProofDocument({ lotteryId, commitmentSha256, commitment, evaluated, headers, secretHex, sources, explorers, frozenAtUnix }) {
  if (evaluated.candidates.length === 0) throw documentError("NO_CANDIDATE_BLOCKS", "there is no candidate block");
  if (selectionSecretCommitment(secretHex) !== commitment.blockRule.selection.secretSha256) {
    throw documentError("SECRET_MISMATCH", "the selection secret does not match the commitment");
  }
  const listSha256 = candidateListSha256(evaluated.candidates);
  const { index, rounds } = selectCandidateIndex(secretHex, listSha256, evaluated.candidates.length);
  const block = evaluated.candidates[index];
  return {
    schema: ON_DEMAND_PROOF_SCHEMA,
    lotteryId,
    commitmentSha256,
    rule: commitment.blockRule.type,
    window: { day: commitment.blockRule.day, timeZone: commitment.blockRule.timeZone, start: commitment.blockRule.windowStart, end: commitment.blockRule.windowEnd },
    frozenAt: toIsoSeconds(frozenAtUnix),
    frozenTipHeight: evaluated.frozenTipHeight,
    candidateCount: evaluated.candidates.length,
    candidatesSha256: listSha256,
    candidates: evaluated.candidates.map((candidate, position) => ({ index: position, height: candidate.height, hash: candidate.hash, medianTime: candidate.medianTime })),
    selection: { method: commitment.blockRule.selection.method, secret: secretHex, secretSha256: commitment.blockRule.selection.secretSha256, index, rounds },
    block: { height: block.height, hash: block.hash, time: block.time, medianTime: block.medianTime },
    headers: headers.map((header) => ({ height: header.height, hex: header.hex })),
    sources: [...sources],
    explorers: explorers.map(({ source, height, hash }) => ({ source, height, hash })),
    seed: deriveSeed(commitmentSha256, block.hash).toString("hex"),
  };
}

// ---- studentLottery.verification.js ----
/**
 * Student delegate lottery — verification of a published bundle.
 *
 * Pure: takes the bytes of the published files, returns a list of checks. No file system, no network.
 * Specification: docs/student-lottery/04-lottery-correctness-and-verification.md §7.
 * This file is inlined into the published verify.mjs.
 *
 * The checks are in two sections, because they establish different things:
 *
 *   draw   — the published results are exactly what the algorithm produces from the committed list,
 *            the committed mandate table and the stated block hash. Complete and self-contained.
 *   block  — the stated block hash comes from a run of headers that is internally valid, carries real
 *            proof of work, and satisfies the announced selection rule. This is strong evidence, not
 *            proof that the headers belong to the most-work Bitcoin chain. See studentLottery.bitcoin.js.
 */

/** Names of the two manifests, relative to the verification folder. */
const MANIFEST_FILES = Object.freeze({
  commitment: "manifest-commitment.json",
  results: "manifest-results.json",
});

/**
 * Check a published manifest: every file it lists must be present with the stated size and SHA-256.
 * `readFile(path)` returns the bytes of a path relative to the lottery folder, or null if it is missing.
 * Paths are taken from an untrusted file, so anything that could leave the folder is refused.
 */
function verifyManifest(manifestBytes, readFile, expected = {}) {
  let manifest;
  try {
    manifest = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes),
    );
  } catch {
    return { status: "FAIL", detail: "the manifest is not valid JSON" };
  }
  if (
    manifest?.schema !== "an-student-lottery/manifest/v1" ||
    !Array.isArray(manifest.files) ||
    manifest.files.length === 0
  ) {
    return { status: "FAIL", detail: "the manifest has an unknown format" };
  }
  if (expected.stage && manifest.stage !== expected.stage)
    return {
      status: "FAIL",
      detail: `the manifest is for stage ${manifest.stage}, expected ${expected.stage}`,
    };
  if (
    expected.commitmentSha256 &&
    manifest.commitmentSha256 !== expected.commitmentSha256
  ) {
    return {
      status: "FAIL",
      detail: "the manifest refers to a different commitment",
    };
  }
  const problems = [];
  for (const file of manifest.files) {
    const path = typeof file?.path === "string" ? file.path : "";
    if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(path) || path.includes("..")) {
      problems.push(`${path || "(no path)"}: unsafe path`);
      continue;
    }
    const bytes = readFile(path);
    if (!bytes) {
      problems.push(`${path}: missing`);
      continue;
    }
    if (bytes.length !== file.bytes || sha256Hex(bytes) !== file.sha256)
      problems.push(`${path}: content differs from the manifest`);
  }
  return problems.length > 0
    ? { status: "FAIL", detail: problems.join("; ") }
    : {
        status: "PASS",
        detail: `${manifest.files.length} files match (${manifest.stage})`,
      };
}

const BUNDLE_FILES = Object.freeze({
  mandates: "mandates.json",
  snapshot: "snapshot.json",
  commitment: "commitment.json",
  proof: "proof.json",
  results: "results.json",
});

class CheckSkipped extends Error {}

/** A prerequisite established by an earlier check; if it is absent this check is skipped, not failed twice. */
function need(value, what) {
  if (!value) throw new CheckSkipped(`not checked: ${what}`);
  return value;
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

function parseFile(files, key) {
  const bytes = files?.[key];
  expect(
    bytes instanceof Uint8Array && bytes.length > 0,
    `${BUNDLE_FILES[key]} is missing or empty`,
  );
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${BUNDLE_FILES[key]} is not valid UTF-8`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${BUNDLE_FILES[key]} is not valid JSON`);
  }
}

/** Reduce a published pool to the fields the algorithm determines; `name` is presentation only. */
function comparablePool(pool) {
  const list = (items) =>
    Array.isArray(items)
      ? items.map((item) => `${item?.rank}:${item?.entryId}:${item?.ticket}`)
      : null;
  return {
    quota: pool?.quota,
    available: pool?.available,
    method: pool?.method,
    vacant: pool?.vacant,
    selected: list(pool?.selected),
    reserve: list(pool?.reserve),
  };
}

/**
 * The v2 rules, checked directly on the recomputed result rather than trusted from the code that made it:
 * per pool selected = min(available, quota), vacant = quota - selected, selected + reserve = available,
 * the method follows from the counts; and the published totals are the sums.
 */
function checkPartialFulfilment(expected, snapshot) {
  const available = new Map();
  for (const entry of snapshot.entries)
    available.set(
      `${entry.group}/${entry.gender}`,
      (available.get(`${entry.group}/${entry.gender}`) || 0) + 1,
    );
  const sums = { allocated: 0, selected: 0, vacant: 0, reserve: 0 };
  let automatic = 0;
  let random = 0;
  for (const group of expected.groups) {
    for (const gender of ["male", "female"]) {
      const pool = group[gender];
      const where = `${group.code}/${gender}`;
      const count = available.get(where) || 0;
      expect(
        pool.available === count,
        `${where}: available is ${pool.available}, the snapshot has ${count}`,
      );
      expect(
        pool.selected.length === Math.min(count, pool.quota),
        `${where}: ${pool.selected.length} selected, expected min(${count}, ${pool.quota})`,
      );
      expect(
        pool.vacant === pool.quota - pool.selected.length,
        `${where}: vacant is ${pool.vacant}, expected ${pool.quota - pool.selected.length}`,
      );
      expect(
        pool.selected.length + pool.reserve.length === count,
        `${where}: selected + reserve is not the pool size`,
      );
      expect(
        pool.method ===
          (count > pool.quota && pool.quota > 0 ? "random" : "automatic"),
        `${where}: method ${pool.method} does not follow from the counts`,
      );
      if (pool.method === "random") random += pool.selected.length;
      else automatic += pool.selected.length;
      sums.allocated += pool.quota;
      sums.selected += pool.selected.length;
      sums.vacant += pool.vacant;
      sums.reserve += pool.reserve.length;
    }
  }
  for (const key of Object.keys(sums)) {
    expect(
      expected.totals?.[key]?.total === sums[key],
      `totals.${key} is ${expected.totals?.[key]?.total}, the pools add up to ${sums[key]}`,
    );
  }
  expect(
    sums.selected + sums.vacant === sums.allocated,
    "selected + vacant is not the number of mandates",
  );
  expect(
    sums.selected + sums.reserve === snapshot.entries.length,
    "selected + reserve is not the number of entries",
  );
  return { ...sums, automatic, random };
}

function firstDifference(expected, published) {
  expect(Array.isArray(published.groups), "results.groups is missing");
  expect(
    published.groups.length === expected.groups.length,
    `results list ${published.groups.length} groups, the computation gives ${expected.groups.length}`,
  );
  for (let index = 0; index < expected.groups.length; index += 1) {
    const want = expected.groups[index];
    const got = published.groups[index];
    expect(
      got?.code === want.code,
      `group #${index + 1} is ${got?.code}, expected ${want.code}`,
    );
    for (const gender of ["male", "female"]) {
      const a = comparablePool(want[gender]);
      const b = comparablePool(got[gender]);
      const where = `${want.code}/${gender}`;
      expect(
        b.quota === a.quota,
        `${where}: quota is ${b.quota}, expected ${a.quota}`,
      );
      for (const field of ["available", "method", "vacant"]) {
        expect(
          b[field] === a[field],
          `${where}: ${field} is ${b[field]}, expected ${a[field]}`,
        );
      }
      for (const list of ["selected", "reserve"]) {
        expect(b[list] !== null, `${where}: ${list} list is missing`);
        expect(
          b[list].length === a[list].length,
          `${where}: ${list} has ${b[list].length} entries, expected ${a[list].length}`,
        );
        for (let rank = 0; rank < a[list].length; rank += 1) {
          expect(
            b[list][rank] === a[list][rank],
            `${where}: ${list} rank ${rank + 1} differs from the computation`,
          );
        }
      }
    }
  }
  if (expected.totals !== undefined) {
    expect(
      JSON.stringify(published.totals) === JSON.stringify(expected.totals),
      "results.totals differ from the computation",
    );
  }
}

/**
 * @param {{mandates, snapshot, commitment, proof, results}} files  bytes of each published file
 * @param {{ params?, rules? }} options  `params` and `rules` exist for tests with synthetic chains and
 *        mandate tables; the published verifier always uses Bitcoin mainnet and the congress allocation.
 * @returns {{ ok: boolean, drawOk: boolean, blockOk: boolean,
 *            checks: {id, section, title, status: "PASS"|"FAIL"|"SKIP", detail}[],
 *            facts: {lotteryId, commitmentSha256, anchor, block, selectedCount} }}
 */
function verifyBundle(
  files,
  { params = BITCOIN_MAINNET, rules = null } = {},
) {
  const checks = [];
  const facts = {
    lotteryId: null,
    commitmentSha256: null,
    anchor: null,
    block: null,
    selectedCount: null,
  };
  const run = (id, section, title, check) => {
    try {
      checks.push({
        id,
        section,
        title,
        status: "PASS",
        detail: check() || "",
      });
      return true;
    } catch (error) {
      const skipped = error instanceof CheckSkipped;
      checks.push({
        id,
        section,
        title,
        status: skipped ? "SKIP" : "FAIL",
        detail: error?.message || String(error),
      });
      return false;
    }
  };

  const doc = {
    mandates: null,
    snapshot: null,
    commitment: null,
    proof: null,
    results: null,
  };
  let commitmentSha256 = null;
  let hashesOk = false;
  let inputsOk = false;
  let headerBlock = null;

  run("D1", "draw", "All five files are present and are valid JSON", () => {
    const problems = [];
    for (const key of Object.keys(BUNDLE_FILES)) {
      try {
        doc[key] = parseFile(files, key);
      } catch (error) {
        problems.push(error.message);
      }
    }
    expect(problems.length === 0, problems.join("; "));
    return Object.values(BUNDLE_FILES).join(", ");
  });

  run(
    "D2",
    "draw",
    "Algorithm version and document schemas are the ones this verifier implements",
    () => {
      const { commitment, proof, results } = doc;
      need(commitment && proof && results, "files could not be read");
      expect(
        commitment.schema === COMMITMENT_SCHEMA,
        `commitment.schema is ${commitment.schema}`,
      );
      const onDemandRule = commitment.blockRule?.type === ON_DEMAND_RULE_TYPE;
      expect(
        proof.schema === (onDemandRule ? ON_DEMAND_PROOF_SCHEMA : PROOF_SCHEMA),
        `proof.schema is ${proof.schema}`,
      );
      // The committed version decides everything below; results may not claim a different one.
      expect(
        SUPPORTED_ALGORITHMS.includes(commitment.algorithm),
        `commitment.algorithm is ${commitment.algorithm}, this verifier implements ${SUPPORTED_ALGORITHMS.join(" and ")}`,
      );
      expect(
        results.algorithm === commitment.algorithm,
        `results.algorithm is ${results.algorithm}, the commitment says ${commitment.algorithm}`,
      );
      expect(
        results.schema === resultsSchemaFor(commitment.algorithm),
        `results.schema is ${results.schema}, expected ${resultsSchemaFor(commitment.algorithm)}`,
      );
      const ids = [
        commitment.lotteryId,
        doc.snapshot?.lotteryId,
        proof.lotteryId,
        results.lotteryId,
      ];
      expect(
        ids.every((id) => typeof id === "string" && id === ids[0]),
        "the files do not all carry the same lotteryId",
      );
      facts.lotteryId = ids[0];
      return `${commitment.algorithm}, lottery ${ids[0]}`;
    },
  );

  const mandatesHashOk = run(
    "D3",
    "draw",
    "mandates.json is the mandate table that was committed to",
    () => {
      need(doc.commitment && doc.mandates, "files could not be read");
      const actual = sha256Hex(files.mandates);
      expect(
        actual === doc.commitment.mandatesSha256,
        `SHA-256 is ${actual}, the commitment says ${doc.commitment.mandatesSha256}`,
      );
      return actual;
    },
  );

  const snapshotHashOk = run(
    "D4",
    "draw",
    "snapshot.json is the participant list that was committed to",
    () => {
      need(doc.commitment && doc.snapshot, "files could not be read");
      const actual = sha256Hex(files.snapshot);
      expect(
        actual === doc.commitment.snapshotSha256,
        `SHA-256 is ${actual}, the commitment says ${doc.commitment.snapshotSha256}`,
      );
      expect(
        doc.snapshot.entryCount === doc.commitment.entryCount,
        "entryCount differs between the snapshot and the commitment",
      );
      expect(
        doc.snapshot.statusFilter === doc.commitment.statusFilter,
        "statusFilter differs between the snapshot and the commitment",
      );
      return `${actual} (${doc.snapshot.entryCount} entries)`;
    },
  );

  const commitmentHashOk = run(
    "D5",
    "draw",
    "proof.json and results.json refer to this commitment.json",
    () => {
      need(
        doc.commitment && doc.proof && doc.results,
        "files could not be read",
      );
      const actual = sha256Hex(files.commitment);
      expect(
        doc.proof.commitmentSha256 === actual,
        `proof.commitmentSha256 is ${doc.proof.commitmentSha256}, the file hashes to ${actual}`,
      );
      expect(
        doc.results.commitmentSha256 === actual,
        `results.commitmentSha256 is ${doc.results.commitmentSha256}, the file hashes to ${actual}`,
      );
      commitmentSha256 = actual;
      facts.commitmentSha256 = actual;
      return actual;
    },
  );
  hashesOk = mandatesHashOk && snapshotHashOk && commitmentHashOk;

  const mandatesOk = run(
    "D6",
    "draw",
    "The mandate table is well formed and its totals add up",
    () => {
      need(doc.mandates, "mandates.json could not be read");
      const result = validateMandates(doc.mandates, rules);
      expect(result.ok, result.errors.map((error) => error.message).join("; "));
      return `${doc.mandates.groups.length} groups, ${result.totals.male} male + ${result.totals.female} female = ${result.totals.total}`;
    },
  );

  const snapshotOk = run(
    "D7",
    "draw",
    "The participant list is well formed: unique ids, known groups, valid genders",
    () => {
      need(doc.snapshot && doc.mandates, "files could not be read");
      const problems = validateSnapshotDocument(doc.snapshot, doc.mandates);
      expect(problems.length === 0, problems.join("; "));
      return `${doc.snapshot.entries.length} entries`;
    },
  );
  inputsOk = hashesOk && mandatesOk && snapshotOk;

  run(
    "D8",
    "draw",
    "The seed is derived from the commitment and the stated block hash",
    () => {
      need(commitmentSha256, "the commitment hash was not established");
      const expected = deriveSeed(
        commitmentSha256,
        doc.results.blockHash,
      ).toString("hex");
      expect(
        doc.results.seed === expected,
        `results.seed is ${doc.results.seed}, expected ${expected}`,
      );
      expect(
        doc.proof.seed === expected,
        `proof.seed is ${doc.proof.seed}, expected ${expected}`,
      );
      return expected;
    },
  );

  const drawOk = run(
    "D9",
    "draw",
    "Recomputing the draw gives exactly the published selected and reserve lists",
    () => {
      need(inputsOk, "the inputs did not pass the checks above");
      // v1: throws QUOTA_UNFILLED if any pool is smaller than its quota; such a draw must never have happened.
      const algorithm = doc.commitment.algorithm;
      const expected = buildResultsDocument({
        mandates: doc.mandates,
        snapshot: doc.snapshot,
        commitmentSha256,
        blockHash: doc.results.blockHash,
        algorithm,
      });
      firstDifference(expected, doc.results);
      const partial =
        algorithm === ALGORITHM_V1
          ? null
          : checkPartialFulfilment(expected, doc.snapshot);
      let selected = 0;
      let reserve = 0;
      const winners = new Set();
      for (const group of expected.groups) {
        for (const gender of ["male", "female"]) {
          selected += group[gender].selected.length;
          reserve += group[gender].reserve.length;
          for (const item of group[gender].selected) winners.add(item.entryId);
        }
      }
      expect(winners.size === selected, "an entry is selected more than once");
      facts.selectedCount = selected;
      if (!partial)
        return `${selected} selected, ${reserve} in reserve, all ranks and tickets match`;
      facts.vacantCount = partial.vacant;
      facts.allocatedCount = partial.allocated;
      return (
        `${selected} selected of ${partial.allocated} mandates (${partial.random} by ranking, ${partial.automatic} automatically), ` +
        `${partial.vacant} vacant, ${reserve} in reserve, all ranks and tickets match`
      );
    },
  );

  if (doc.commitment?.blockRule?.type === ON_DEMAND_RULE_TYPE) {
    verifyOnDemandBlock({ doc, run, need, checks, facts, params });
    return finish(checks, facts, drawOk);
  }

  run(
    "B1",
    "block",
    "The block rule in the commitment is the one this verifier implements",
    () => {
      const rule = need(
        doc.commitment,
        "commitment.json could not be read",
      ).blockRule;
      expect(
        rule && typeof rule === "object",
        "commitment.blockRule is missing",
      );
      expect(rule.network === BITCOIN_NETWORK, `network is ${rule.network}`);
      expect(rule.type === BLOCK_RULE_TYPE, `rule type is ${rule.type}`);
      expect(
        Number.isSafeInteger(rule.confirmations) && rule.confirmations >= 1,
        "confirmations must be an integer of at least 1",
      );
      expect(
        fromIsoSeconds(rule.targetTime) === rule.targetTimeUnix,
        "targetTime and targetTimeUnix disagree",
      );
      const lockedAt = fromIsoSeconds(doc.commitment.lockedAt);
      expect(lockedAt !== null, "lockedAt is not a UTC timestamp");
      expect(
        rule.targetTimeUnix - lockedAt >= COMMIT_LEAD_SECONDS,
        "the commitment states it was locked less than three hours before the target time",
      );
      return `first block with median-time-past >= ${rule.targetTime}, ${rule.confirmations} confirmations`;
    },
  );

  const blockOk = run(
    "B2",
    "block",
    "The headers carry valid proof of work, link together and select the stated block",
    () => {
      need(
        checks.find((check) => check.id === "B1")?.status === "PASS",
        "the block rule was not accepted",
      );
      need(doc.proof, "proof.json could not be read");
      expect(Array.isArray(doc.proof.headers), "proof.headers is missing");
      const result = evaluateBlockRule({
        headers: doc.proof.headers,
        targetTimeUnix: doc.commitment.blockRule.targetTimeUnix,
        confirmations: doc.commitment.blockRule.confirmations,
        anchor: doc.commitment.anchor,
        params,
      });
      expect(
        result.status === "confirmed",
        `the headers do not confirm a block yet (${result.reason})`,
      );
      const stated = doc.proof.block || {};
      expect(
        stated.height === result.block.height,
        `proof.block.height is ${stated.height}, the headers select ${result.block.height}`,
      );
      expect(
        stated.hash === result.block.hash,
        `proof.block.hash is ${stated.hash}, the headers select ${result.block.hash}`,
      );
      expect(
        stated.medianTime === result.block.medianTime,
        "proof.block.medianTime does not match the headers",
      );
      expect(
        stated.previousMedianTime === result.block.previousMedianTime,
        "proof.block.previousMedianTime does not match the headers",
      );
      headerBlock = result.block;
      facts.block = { height: result.block.height, hash: result.block.hash };
      facts.anchor = {
        height: doc.commitment.anchor.height,
        hash: doc.commitment.anchor.hash,
      };
      return `block ${result.block.height} ${result.block.hash}, ${result.confirmations} confirmations in the proof`;
    },
  );

  run(
    "B3",
    "block",
    "The draw used the block selected by the headers, not some other hash",
    () => {
      need(headerBlock, "no block was established from the headers");
      need(doc.results, "results.json could not be read");
      expect(
        doc.results.blockHash === headerBlock.hash,
        `results.blockHash is ${doc.results.blockHash}, the headers select ${headerBlock.hash}`,
      );
      return headerBlock.hash;
    },
  );

  return finish(checks, facts, drawOk, blockOk);
}

function finish(checks, facts, drawOk, blockOk = true) {
  const failed = checks.filter((check) => check.status !== "PASS");
  return {
    ok: failed.length === 0,
    drawOk:
      drawOk &&
      checks
        .filter((check) => check.section === "draw")
        .every((check) => check.status === "PASS"),
    blockOk:
      blockOk &&
      checks
        .filter((check) => check.section === "block")
        .every((check) => check.status === "PASS"),
    checks,
    facts,
  };
}

/**
 * Section B for the on-demand rule. Establishes: the rule and day window are as committed; the published
 * candidate list is exactly what the rule gives on the published headers; the revealed secret matches its
 * commitment; the index and therefore the block follow from the secret and the list; the draw used that
 * block. It cannot establish when the server froze the list or that it did not try other freeze moments.
 */
function verifyOnDemandBlock({ doc, run, need, checks, facts, params }) {
  let evaluated = null;
  let selected = null;
  run(
    "B1",
    "block",
    "The on-demand rule in the commitment is the one this verifier implements",
    () => {
      const rule = need(
        doc.commitment,
        "commitment.json could not be read",
      ).blockRule;
      expect(rule.network === BITCOIN_NETWORK, `network is ${rule.network}`);
      const window = dayWindow(rule.day);
      expect(
        rule.windowStartUnix === window.startUnix &&
          rule.windowEndUnix === window.endUnix,
        `the window does not match day ${rule.day} in Asia/Ulaanbaatar`,
      );
      expect(
        rule.windowStart === window.start && rule.windowEnd === window.end,
        "windowStart/windowEnd disagree with the Unix times",
      );
      expect(
        rule.timestamp === "median-time-past" && rule.minedAfterAnchor === true,
        "unknown timestamp or anchor policy",
      );
      expect(
        Number.isSafeInteger(rule.confirmations) && rule.confirmations >= 1,
        "confirmations must be an integer of at least 1",
      );
      expect(
        rule.selection?.method === ON_DEMAND_SELECTION_METHOD &&
          /^[0-9a-f]{64}$/.test(rule.selection?.secretSha256 ?? ""),
        "unknown selection method or malformed secret commitment",
      );
      const lockedAt = fromIsoSeconds(doc.commitment.lockedAt);
      expect(
        lockedAt !== null && lockedAt < window.endUnix,
        "the commitment was locked after the lottery day ended",
      );
      return `blocks with median-time-past on ${rule.day} (${window.start} … ${window.end}), mined after anchor #${doc.commitment.anchor?.height}, ${rule.confirmations} confirmations`;
    },
  );

  run(
    "B2",
    "block",
    "The headers carry valid proof of work, link to the anchor, and give exactly the published candidate list",
    () => {
      need(
        checks.find((check) => check.id === "B1")?.status === "PASS",
        "the rule was not accepted",
      );
      const proof = need(doc.proof, "proof.json could not be read");
      const rule = doc.commitment.blockRule;
      expect(
        Array.isArray(proof.headers) && Array.isArray(proof.candidates),
        "proof.headers or proof.candidates is missing",
      );
      evaluated = evaluateDayCandidates({
        headers: proof.headers,
        window: dayWindow(rule.day),
        confirmations: rule.confirmations,
        anchor: doc.commitment.anchor,
        params,
      });
      expect(
        evaluated.candidates.length > 0,
        "the headers give no candidate block",
      );
      expect(
        proof.frozenTipHeight === evaluated.frozenTipHeight,
        `proof.frozenTipHeight is ${proof.frozenTipHeight}, the headers end at ${evaluated.frozenTipHeight}`,
      );
      expect(
        proof.candidates.length === evaluated.candidates.length,
        `${proof.candidates.length} candidates published, the headers give ${evaluated.candidates.length}`,
      );
      evaluated.candidates.forEach((candidate, index) => {
        const published = proof.candidates[index];
        expect(
          published?.index === index &&
            published.height === candidate.height &&
            published.hash === candidate.hash,
          `candidate #${index} differs from the headers`,
        );
      });
      expect(
        proof.candidateCount === evaluated.candidates.length,
        "proof.candidateCount is wrong",
      );
      expect(
        proof.candidatesSha256 === candidateListSha256(evaluated.candidates),
        "proof.candidatesSha256 does not match the list",
      );
      facts.anchor = {
        height: doc.commitment.anchor.height,
        hash: doc.commitment.anchor.hash,
      };
      return `${evaluated.candidates.length} candidate blocks, heights ${evaluated.candidates[0].height}–${evaluated.candidates.at(-1).height}, frozen at tip ${evaluated.frozenTipHeight}`;
    },
  );

  run(
    "B3",
    "block",
    "The revealed secret matches its commitment and selects the block the draw used",
    () => {
      need(evaluated, "the candidate list was not established");
      const proof = doc.proof;
      const rule = doc.commitment.blockRule;
      expect(
        selectionSecretCommitment(proof.selection?.secret) ===
          rule.selection.secretSha256,
        "SHA-256 of the revealed secret is not the committed value",
      );
      const { index } = selectCandidateIndex(
        proof.selection.secret,
        proof.candidatesSha256,
        evaluated.candidates.length,
      );
      expect(
        proof.selection.index === index,
        `proof.selection.index is ${proof.selection.index}, the secret gives ${index}`,
      );
      selected = evaluated.candidates[index];
      expect(
        proof.block?.height === selected.height &&
          proof.block?.hash === selected.hash,
        "proof.block is not the selected candidate",
      );
      expect(
        doc.results?.blockHash === selected.hash,
        `results.blockHash is ${doc.results?.blockHash}, the selection gives ${selected.hash}`,
      );
      facts.block = { height: selected.height, hash: selected.hash };
      facts.selection = { index, candidates: evaluated.candidates.length };
      return `index ${index} of ${evaluated.candidates.length}: block ${selected.height} ${selected.hash}. Not provable here: when the server froze the list, or whether it tried other moments.`;
    },
  );
}

// ---- studentLottery.verifyCli.js ----
/**
 * Student delegate lottery — command-line verifier.
 *
 * In this repository:  node modules/studentLottery/studentLottery.verifyCli.js <bundle-dir> [--online]
 * Published form:      node verify.mjs [--online]      (built by studentLottery.verifyBuilder.js)
 *
 * Needs only the published files. No database, no admin API, no secret.
 * Exit code 0: every check passed. 1: at least one check failed. 2: could not run.
 */

const ONLINE_SOURCES = ["https://mempool.space/api", "https://blockstream.info/api"];

function readBundle(directory) {
  const files = {};
  for (const [key, name] of Object.entries(BUNDLE_FILES)) {
    try {
      files[key] = readFileSync(join(directory, name));
    } catch {
      files[key] = null;
    }
  }
  return files;
}

/**
 * The manifests list every published file with its hash. They sit next to this script; the files they
 * name are relative to the folder above it. A bundle without manifests (downloaded before publication)
 * is reported as such, not as a failure.
 */
function checkManifests(directory, commitmentSha256) {
  const root = join(directory, "..");
  const read = (path) => { try { return readFileSync(join(root, path)); } catch { return null; } };
  const lines = [];
  let ok = true;
  let found = 0;
  for (const [stage, name] of Object.entries(MANIFEST_FILES)) {
    let bytes;
    try { bytes = readFileSync(join(directory, name)); } catch { continue; }
    found += 1;
    const result = verifyManifest(bytes, read, { stage, commitmentSha256 });
    if (result.status !== "PASS") ok = false;
    lines.push(`  [${result.status}] M  ${name}\n         ${result.detail}`);
  }
  return { ok, lines, found };
}

/** Ask public explorers which block is at a height. Explorers are third parties; this is corroboration. */
async function checkOnline(facts, fetchImpl) {
  const lines = [];
  let ok = true;
  for (const [label, block] of [["anchor block", facts.anchor], ["target block", facts.block]]) {
    for (const source of ONLINE_SOURCES) {
      let status = "PASS";
      let detail = "";
      try {
        const response = await fetchImpl(`${source}/block-height/${block.height}`, { signal: AbortSignal.timeout(15_000) });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const hash = (await response.text()).trim();
        if (hash !== block.hash) {
          status = "FAIL";
          detail = `${source} reports ${hash}`;
        } else {
          detail = `${source} agrees`;
        }
      } catch (error) {
        status = "FAIL";
        detail = `${source} could not be reached (${error?.message || error})`;
      }
      if (status !== "PASS") ok = false;
      lines.push(`  [${status}] C  ${label} at height ${block.height}: ${detail}`);
    }
  }
  return { ok, lines };
}

async function runVerifier({ directory, online = false, fetchImpl = globalThis.fetch, print = console.log }) {
  const result = verifyBundle(readBundle(directory));
  const section = (name) => result.checks.filter((check) => check.section === name);
  const show = (check) => print(`  [${check.status}] ${check.id} ${check.title}${check.detail ? `\n         ${check.detail}` : ""}`);

  print(`Student delegate lottery verification — ${resolve(directory)}`);
  print("");
  print("A. Draw computation (complete: needs nothing but these files)");
  section("draw").forEach(show);
  print("");
  print("B. Bitcoin block evidence (offline: header proof of work, linkage and the selection rule)");
  section("block").forEach(show);

  const manifests = checkManifests(directory, result.facts.commitmentSha256);
  print("");
  print("M. Published files (every file named in a manifest is present and unchanged)");
  if (manifests.found === 0) print("  [SKIP] M  no manifest in this folder (not a published copy)");
  manifests.lines.forEach((line) => print(line));

  let onlineOk = true;
  if (online) {
    print("");
    print("C. Public explorers (online corroboration that the blocks are on the Bitcoin main chain)");
    if (!result.facts.block || !result.facts.anchor) {
      onlineOk = false;
      print("  [SKIP] C  no block was established in section B");
    } else {
      const outcome = await checkOnline(result.facts, fetchImpl);
      onlineOk = outcome.ok;
      outcome.lines.forEach((line) => print(line));
    }
  }

  const ok = result.ok && onlineOk && manifests.ok;
  print("");
  print(`Draw computation:  ${result.drawOk ? "PASS" : "FAIL"}`);
  print(`Block evidence:    ${result.blockOk ? "PASS" : "FAIL"}`);
  if (manifests.found > 0) print(`Published files:   ${manifests.ok ? "PASS" : "FAIL"}`);
  if (online) print(`Public explorers:  ${onlineOk ? "PASS" : "FAIL"}`);
  print(`RESULT: ${ok ? "PASS" : "FAIL"}`);
  print("");
  print("What this does and does not establish:");
  print("  - Section A fully verifies the calculation: given the committed list, the committed mandate table");
  print("    and the stated block hash, the published selected and reserve lists are the only possible result.");
  print("  - Section B verifies that the block hash comes from real proof-of-work headers that satisfy the");
  print("    announced rule. It cannot by itself prove those headers are on the most-work Bitcoin chain, and");
  print("    block heights are stated, not proven.");
  if (!online) {
    print("  - Chain membership was NOT checked in this run. Run again with --online, or better, ask your own");
    print("    Bitcoin node.");
  } else {
    print("  - Section C compared the blocks with two public explorers, which are third parties. For a check");
    print("    that trusts no one, ask your own Bitcoin node.");
  }
  if (result.facts.block) {
    print(`      bitcoin-cli getblockhash ${result.facts.block.height}   # expect ${result.facts.block.hash}`);
    print(`      bitcoin-cli getblockhash ${result.facts.anchor.height}   # expect ${result.facts.anchor.hash}`);
  }
  print("  - That commitment.json was public before the target time is shown by where and when it was");
  print("    published, not by this script.");
  return ok;
}

async function main(argv) {
  const flags = argv.filter((arg) => arg.startsWith("--"));
  const positional = argv.filter((arg) => !arg.startsWith("--"));
  const unknown = flags.filter((flag) => flag !== "--online");
  if (unknown.length > 0 || positional.length > 1) {
    console.error("Usage: node verify.mjs [directory] [--online]");
    return 2;
  }
  const directory = positional[0] ? resolve(positional[0]) : dirname(fileURLToPath(import.meta.url));
  try {
    return (await runVerifier({ directory, online: flags.includes("--online") })) ? 0 : 1;
  } catch (error) {
    console.error(`Verification could not run: ${error?.message || error}`);
    return 2;
  }
}

function isEntryPoint() {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

// In the published verify.mjs the builder replaces this line with `true`: that file is only ever run directly,
// and a verifier that silently does nothing would look like a pass.
const INVOKED_DIRECTLY = true;
if (INVOKED_DIRECTLY) process.exitCode = await main(process.argv.slice(2));
