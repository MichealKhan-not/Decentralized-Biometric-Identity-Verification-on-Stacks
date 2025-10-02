// tests/biometric-verifier.test.ts

import { describe, it, expect, beforeEach } from "vitest";
import { stringAsciiCV, uintCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_HASH_LENGTH = 101;
const ERR_INVALID_SALT = 102;
const ERR_INVALID_EXPIRATION = 103;
const ERR_INVALID_BIOMETRIC_TYPE = 115;
const ERR_INVALID_CONFIDENCE_SCORE = 116;
const ERR_INVALID_GRACE_PERIOD = 117;
const ERR_INVALID_LOCATION = 118;
const ERR_INVALID_DEVICE_ID = 119;
const ERR_INVALID_MIN_CONFIDENCE = 110;
const ERR_INVALID_MAX_ATTEMPTS = 111;
const ERR_MAX_VERIFICATIONS_EXCEEDED = 114;
const ERR_INVALID_UPDATE_PARAM = 113;
const ERR_AUTHORITY_NOT_VERIFIED = 109;
const ERR_IDENTITY_ALREADY_VERIFIED = 106;
const ERR_IDENTITY_NOT_FOUND = 107;
const ERR_VERIFICATION_EXPIRED = 112;
const ERR_ATTEMPTS_EXCEEDED = 121;
const ERR_HASH_MISMATCH = 122;
const ERR_SALT_MISMATCH = 123;

interface Verification {
  user: string;
  biometricHash: string;
  salt: number;
  expiration: number;
  timestamp: number;
  verifier: string;
  biometricType: string;
  confidenceScore: number;
  gracePeriod: number;
  location: string;
  deviceId: string;
  status: boolean;
  minConfidence: number;
  maxAttempts: number;
  attempts: number;
}

interface VerificationUpdate {
  updateHash: string;
  updateSalt: number;
  updateExpiration: number;
  updateTimestamp: number;
  updater: string;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class BiometricVerifierMock {
  state: {
    nextVerificationId: number;
    maxVerifications: number;
    verificationFee: number;
    authorityContract: string | null;
    verifications: Map<number, Verification>;
    verificationUpdates: Map<number, VerificationUpdate>;
    verificationsByUser: Map<string, number>;
  } = {
    nextVerificationId: 0,
    maxVerifications: 10000,
    verificationFee: 500,
    authorityContract: null,
    verifications: new Map(),
    verificationUpdates: new Map(),
    verificationsByUser: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";
  authorities: Set<string> = new Set(["ST1TEST"]);
  stxTransfers: Array<{ amount: number; from: string; to: string | null }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextVerificationId: 0,
      maxVerifications: 10000,
      verificationFee: 500,
      authorityContract: null,
      verifications: new Map(),
      verificationUpdates: new Map(),
      verificationsByUser: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
    this.authorities = new Set(["ST1TEST"]);
    this.stxTransfers = [];
  }

  isVerifiedAuthority(principal: string): Result<boolean> {
    return { ok: true, value: this.authorities.has(principal) };
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78") {
      return { ok: false, value: false };
    }
    if (this.state.authorityContract !== null) {
      return { ok: false, value: false };
    }
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setVerificationFee(newFee: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: false };
    this.state.verificationFee = newFee;
    return { ok: true, value: true };
  }

  initiateVerification(
    user: string,
    biometricHash: string,
    salt: number,
    expiration: number,
    biometricType: string,
    confidenceScore: number,
    gracePeriod: number,
    location: string,
    deviceId: string,
    minConfidence: number,
    maxAttempts: number
  ): Result<number> {
    if (this.state.nextVerificationId >= this.state.maxVerifications) return { ok: false, value: ERR_MAX_VERIFICATIONS_EXCEEDED };
    if (biometricHash.length !== 64) return { ok: false, value: ERR_INVALID_HASH_LENGTH };
    if (salt <= 0) return { ok: false, value: ERR_INVALID_SALT };
    if (expiration <= this.blockHeight) return { ok: false, value: ERR_INVALID_EXPIRATION };
    if (!["fingerprint", "facial", "iris"].includes(biometricType)) return { ok: false, value: ERR_INVALID_BIOMETRIC_TYPE };
    if (confidenceScore < 0 || confidenceScore > 100) return { ok: false, value: ERR_INVALID_CONFIDENCE_SCORE };
    if (gracePeriod > 30) return { ok: false, value: ERR_INVALID_GRACE_PERIOD };
    if (location.length > 100) return { ok: false, value: ERR_INVALID_LOCATION };
    if (deviceId.length > 64) return { ok: false, value: ERR_INVALID_DEVICE_ID };
    if (minConfidence < 0 || minConfidence > 100) return { ok: false, value: ERR_INVALID_MIN_CONFIDENCE };
    if (maxAttempts <= 0) return { ok: false, value: ERR_INVALID_MAX_ATTEMPTS };
    if (!this.isVerifiedAuthority(this.caller).value) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (this.state.verificationsByUser.has(user)) return { ok: false, value: ERR_IDENTITY_ALREADY_VERIFIED };
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };

    this.stxTransfers.push({ amount: this.state.verificationFee, from: this.caller, to: this.state.authorityContract });

    const id = this.state.nextVerificationId;
    const verification: Verification = {
      user,
      biometricHash,
      salt,
      expiration,
      timestamp: this.blockHeight,
      verifier: this.caller,
      biometricType,
      confidenceScore,
      gracePeriod,
      location,
      deviceId,
      status: false,
      minConfidence,
      maxAttempts,
      attempts: 0,
    };
    this.state.verifications.set(id, verification);
    this.state.verificationsByUser.set(user, id);
    this.state.nextVerificationId++;
    return { ok: true, value: id };
  }

  getVerification(id: number): Verification | null {
    return this.state.verifications.get(id) || null;
  }

  performVerification(id: number, submittedHash: string, submittedSalt: number, submittedConfidence: number): Result<boolean> {
    const verification = this.state.verifications.get(id);
    if (!verification) return { ok: false, value: false };
    if (verification.verifier !== this.caller) return { ok: false, value: false };
    if (this.blockHeight > verification.expiration) return { ok: false, value: false };
    if (verification.attempts >= verification.maxAttempts) return { ok: false, value: false };
    if (submittedHash.length !== 64) return { ok: false, value: false };
    if (submittedSalt <= 0) return { ok: false, value: false };
    if (submittedConfidence < 0 || submittedConfidence > 100) return { ok: false, value: false };
    if (submittedHash !== verification.biometricHash) return { ok: false, value: false };
    if (submittedSalt !== verification.salt) return { ok: false, value: false };
    if (submittedConfidence < verification.minConfidence) return { ok: false, value: false };

    const updated: Verification = {
      ...verification,
      status: true,
      timestamp: this.blockHeight,
      confidenceScore: submittedConfidence,
      attempts: verification.attempts + 1,
    };
    this.state.verifications.set(id, updated);
    return { ok: true, value: true };
  }

  updateVerification(id: number, updateHash: string, updateSalt: number, updateExpiration: number): Result<boolean> {
    const verification = this.state.verifications.get(id);
    if (!verification) return { ok: false, value: false };
    if (verification.verifier !== this.caller) return { ok: false, value: false };
    if (updateHash.length !== 64) return { ok: false, value: false };
    if (updateSalt <= 0) return { ok: false, value: false };
    if (updateExpiration <= this.blockHeight) return { ok: false, value: false };

    const updated: Verification = {
      ...verification,
      biometricHash: updateHash,
      salt: updateSalt,
      expiration: updateExpiration,
      timestamp: this.blockHeight,
    };
    this.state.verifications.set(id, updated);
    this.state.verificationUpdates.set(id, {
      updateHash,
      updateSalt,
      updateExpiration,
      updateTimestamp: this.blockHeight,
      updater: this.caller,
    });
    return { ok: true, value: true };
  }

  revokeVerification(id: number): Result<boolean> {
    const verification = this.state.verifications.get(id);
    if (!verification) return { ok: false, value: false };
    if (verification.user !== this.caller && verification.verifier !== this.caller) return { ok: false, value: false };

    this.state.verifications.delete(id);
    this.state.verificationsByUser.delete(verification.user);
    this.state.verificationUpdates.delete(id);
    return { ok: true, value: true };
  }

  getVerificationCount(): Result<number> {
    return { ok: true, value: this.state.nextVerificationId };
  }

  checkUserVerification(user: string): Result<boolean> {
    return { ok: true, value: this.state.verificationsByUser.has(user) };
  }

  incrementAttempt(id: number): Result<boolean> {
    const verification = this.state.verifications.get(id);
    if (!verification) return { ok: false, value: false };
    if (verification.verifier !== this.caller) return { ok: false, value: false };
    if (verification.attempts >= verification.maxAttempts) return { ok: false, value: false };

    const updated: Verification = {
      ...verification,
      attempts: verification.attempts + 1,
    };
    this.state.verifications.set(id, updated);
    return { ok: true, value: true };
  }

  resetAttempts(id: number): Result<boolean> {
    const verification = this.state.verifications.get(id);
    if (!verification) return { ok: false, value: false };
    if (verification.verifier !== this.caller) return { ok: false, value: false };

    const updated: Verification = {
      ...verification,
      attempts: 0,
    };
    this.state.verifications.set(id, updated);
    return { ok: true, value: true };
  }
}

describe("BiometricVerifier", () => {
  let contract: BiometricVerifierMock;

  beforeEach(() => {
    contract = new BiometricVerifierMock();
    contract.reset();
  });

  it("initiates a verification successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);

    const verification = contract.getVerification(0);
    expect(verification?.user).toBe("STUSER");
    expect(verification?.biometricHash).toBe("a".repeat(64));
    expect(verification?.salt).toBe(12345);
    expect(verification?.expiration).toBe(1000);
    expect(verification?.biometricType).toBe("fingerprint");
    expect(verification?.confidenceScore).toBe(90);
    expect(verification?.gracePeriod).toBe(7);
    expect(verification?.location).toBe("LocationX");
    expect(verification?.deviceId).toBe("Device123");
    expect(verification?.minConfidence).toBe(80);
    expect(verification?.maxAttempts).toBe(3);
    expect(verification?.attempts).toBe(0);
    expect(verification?.status).toBe(false);
    expect(contract.stxTransfers).toEqual([{ amount: 500, from: "ST1TEST", to: "ST2TEST" }]);
  });

  it("rejects duplicate user verification", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.initiateVerification(
      "STUSER",
      "b".repeat(64),
      67890,
      2000,
      "facial",
      95,
      14,
      "LocationY",
      "Device456",
      85,
      5
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_IDENTITY_ALREADY_VERIFIED);
  });

  it("rejects non-authorized caller", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.caller = "ST2FAKE";
    contract.authorities = new Set();
    const result = contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects verification initiation without authority contract", () => {
    const result = contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUTHORITY_NOT_VERIFIED);
  });

  it("rejects invalid hash length", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.initiateVerification(
      "STUSER",
      "short",
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_HASH_LENGTH);
  });

  it("rejects invalid biometric type", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "invalid",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_BIOMETRIC_TYPE);
  });

  it("performs verification successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.performVerification(0, "a".repeat(64), 12345, 85);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const verification = contract.getVerification(0);
    expect(verification?.status).toBe(true);
    expect(verification?.confidenceScore).toBe(85);
    expect(verification?.attempts).toBe(1);
  });

  it("rejects perform verification for non-existent id", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.performVerification(99, "a".repeat(64), 12345, 85);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects perform verification by non-verifier", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.caller = "ST3FAKE";
    const result = contract.performVerification(0, "a".repeat(64), 12345, 85);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects perform verification if expired", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.blockHeight = 1001;
    const result = contract.performVerification(0, "a".repeat(64), 12345, 85);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects perform verification if attempts exceeded", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.performVerification(0, "a".repeat(64), 12345, 85);
    contract.performVerification(0, "a".repeat(64), 12345, 85);
    contract.performVerification(0, "a".repeat(64), 12345, 85);
    const result = contract.performVerification(0, "a".repeat(64), 12345, 85);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects perform verification on hash mismatch", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.performVerification(0, "b".repeat(64), 12345, 85);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects perform verification on salt mismatch", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.performVerification(0, "a".repeat(64), 67890, 85);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects perform verification if confidence too low", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.performVerification(0, "a".repeat(64), 12345, 70);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("updates verification successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.updateVerification(0, "b".repeat(64), 67890, 2000);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const verification = contract.getVerification(0);
    expect(verification?.biometricHash).toBe("b".repeat(64));
    expect(verification?.salt).toBe(67890);
    expect(verification?.expiration).toBe(2000);
    const update = contract.state.verificationUpdates.get(0);
    expect(update?.updateHash).toBe("b".repeat(64));
    expect(update?.updateSalt).toBe(67890);
    expect(update?.updateExpiration).toBe(2000);
    expect(update?.updater).toBe("ST1TEST");
  });

  it("rejects update for non-existent verification", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.updateVerification(99, "b".repeat(64), 67890, 2000);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects update by non-verifier", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.caller = "ST3FAKE";
    const result = contract.updateVerification(0, "b".repeat(64), 67890, 2000);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("revokes verification successfully by user", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.caller = "STUSER";
    const result = contract.revokeVerification(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getVerification(0)).toBe(null);
    expect(contract.state.verificationsByUser.has("STUSER")).toBe(false);
    expect(contract.state.verificationUpdates.has(0)).toBe(false);
  });

  it("revokes verification successfully by verifier", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.revokeVerification(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getVerification(0)).toBe(null);
    expect(contract.state.verificationsByUser.has("STUSER")).toBe(false);
    expect(contract.state.verificationUpdates.has(0)).toBe(false);
  });

  it("rejects revoke by unauthorized", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.caller = "ST3FAKE";
    const result = contract.revokeVerification(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("sets verification fee successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.setVerificationFee(1000);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.verificationFee).toBe(1000);
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    expect(contract.stxTransfers).toEqual([{ amount: 1000, from: "ST1TEST", to: "ST2TEST" }]);
  });

  it("rejects verification fee change without authority contract", () => {
    const result = contract.setVerificationFee(1000);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("returns correct verification count", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER1",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.initiateVerification(
      "STUSER2",
      "b".repeat(64),
      67890,
      2000,
      "facial",
      95,
      14,
      "LocationY",
      "Device456",
      85,
      5
    );
    const result = contract.getVerificationCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("checks user verification correctly", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.checkUserVerification("STUSER");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const result2 = contract.checkUserVerification("NONUSER");
    expect(result2.ok).toBe(true);
    expect(result2.value).toBe(false);
  });

  it("parses verification parameters with Clarity types", () => {
    const hash = stringAsciiCV("a".repeat(64));
    const salt = uintCV(12345);
    expect(hash.value).toBe("a".repeat(64));
    expect(salt.value).toEqual(BigInt(12345));
  });

  it("rejects verification initiation with invalid expiration", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      0,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_EXPIRATION);
  });

  it("rejects verification initiation with max verifications exceeded", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.state.maxVerifications = 1;
    contract.initiateVerification(
      "STUSER1",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.initiateVerification(
      "STUSER2",
      "b".repeat(64),
      67890,
      2000,
      "facial",
      95,
      14,
      "LocationY",
      "Device456",
      85,
      5
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_VERIFICATIONS_EXCEEDED);
  });

  it("sets authority contract successfully", () => {
    const result = contract.setAuthorityContract("ST2TEST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("ST2TEST");
  });

  it("rejects invalid authority contract", () => {
    const result = contract.setAuthorityContract("SP000000000000000000002Q6VF78");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("increments attempt successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    const result = contract.incrementAttempt(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const verification = contract.getVerification(0);
    expect(verification?.attempts).toBe(1);
  });

  it("rejects increment attempt for non-existent verification", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.incrementAttempt(99);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects increment attempt by non-verifier", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.caller = "ST3FAKE";
    const result = contract.incrementAttempt(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects increment attempt if max exceeded", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.incrementAttempt(0);
    contract.incrementAttempt(0);
    contract.incrementAttempt(0);
    const result = contract.incrementAttempt(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("resets attempts successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.incrementAttempt(0);
    contract.incrementAttempt(0);
    const result = contract.resetAttempts(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const verification = contract.getVerification(0);
    expect(verification?.attempts).toBe(0);
  });

  it("rejects reset attempts for non-existent verification", () => {
    contract.setAuthorityContract("ST2TEST");
    const result = contract.resetAttempts(99);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects reset attempts by non-verifier", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.initiateVerification(
      "STUSER",
      "a".repeat(64),
      12345,
      1000,
      "fingerprint",
      90,
      7,
      "LocationX",
      "Device123",
      80,
      3
    );
    contract.caller = "ST3FAKE";
    const result = contract.resetAttempts(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });
});