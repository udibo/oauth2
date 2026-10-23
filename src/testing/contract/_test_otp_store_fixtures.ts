import type { OtpRecord, OtpStore } from "../../identity/otp.ts";

export type OtpStoreFault =
  | "consume-keeps-older"
  | "consume-retires-newer"
  | "failed-consume-retires"
  | "consume-retires-every-pair"
  | "find-active-by-insertion";

export class ManyCodeOtpStore implements OtpStore {
  readonly #fault?: OtpStoreFault;
  readonly #records = new Map<string, OtpRecord>();
  readonly #active = new Set<string>();

  constructor(fault?: OtpStoreFault) {
    this.#fault = fault;
  }

  create(record: OtpRecord): Promise<void> {
    this.#records.set(record.id, { ...record });
    this.#active.add(record.id);
    return Promise.resolve();
  }

  findActive(email: string, purpose: string): Promise<OtpRecord | null> {
    let latest: OtpRecord | null = null;
    for (const record of this.#activeFor(email, purpose)) {
      if (
        !latest ||
        this.#fault === "find-active-by-insertion" ||
        record.createdAt >= latest.createdAt
      ) {
        latest = record;
      }
    }
    return Promise.resolve(latest && { ...latest });
  }

  recordAttempt(id: string): Promise<number> {
    const record = this.#records.get(id);
    if (!record) return Promise.resolve(0);
    record.attempts++;
    return Promise.resolve(record.attempts);
  }

  consume(id: string): Promise<boolean> {
    const claimed = this.#active.delete(id);
    const record = this.#records.get(id);
    const retires =
      this.#fault !== "consume-keeps-older" &&
      (claimed || this.#fault === "failed-consume-retires");
    if (record && retires) {
      const candidates =
        this.#fault === "consume-retires-every-pair"
          ? this.#allActive()
          : this.#activeFor(record.email, record.purpose);
      for (const other of candidates) {
        if (
          this.#fault === "consume-retires-newer" ||
          other.createdAt <= record.createdAt
        ) {
          this.#active.delete(other.id);
        }
      }
    }
    return Promise.resolve(claimed);
  }

  invalidateById(id: string): Promise<void> {
    this.#active.delete(id);
    return Promise.resolve();
  }

  invalidate(email: string, purpose: string): Promise<void> {
    for (const record of this.#activeFor(email, purpose)) {
      this.#active.delete(record.id);
    }
    return Promise.resolve();
  }

  #activeFor(email: string, purpose: string): OtpRecord[] {
    return this.#allActive().filter(
      (record) => record.email === email && record.purpose === purpose,
    );
  }

  #allActive(): OtpRecord[] {
    return [...this.#active]
      .map((id) => this.#records.get(id))
      .filter((record): record is OtpRecord => record !== undefined);
  }
}

export class OneCodeOtpStore implements OtpStore {
  readonly #codes = new Map<string, OtpRecord>();
  readonly #keepsReplacedId: boolean;

  constructor(options: { keepsReplacedId?: boolean } = {}) {
    this.#keepsReplacedId = options.keepsReplacedId ?? false;
  }

  create(record: OtpRecord): Promise<void> {
    const key = pairKey(record.email, record.purpose);
    const replaced = this.#codes.get(key);
    const id =
      this.#keepsReplacedId && replaced !== undefined ? replaced.id : record.id;
    this.#codes.set(key, { ...record, id });
    return Promise.resolve();
  }

  findActive(email: string, purpose: string): Promise<OtpRecord | null> {
    const record = this.#codes.get(pairKey(email, purpose));
    return Promise.resolve(record ? { ...record } : null);
  }

  recordAttempt(id: string): Promise<number> {
    const record = this.#byId(id);
    if (!record) return Promise.resolve(0);
    record.attempts++;
    return Promise.resolve(record.attempts);
  }

  consume(id: string): Promise<boolean> {
    const record = this.#byId(id);
    if (!record) return Promise.resolve(false);
    this.#codes.delete(pairKey(record.email, record.purpose));
    return Promise.resolve(true);
  }

  async invalidateById(id: string): Promise<void> {
    await this.consume(id);
  }

  invalidate(email: string, purpose: string): Promise<void> {
    this.#codes.delete(pairKey(email, purpose));
    return Promise.resolve();
  }

  #byId(id: string): OtpRecord | undefined {
    return [...this.#codes.values()].find((record) => record.id === id);
  }
}

function pairKey(email: string, purpose: string): string {
  return `${purpose}\n${email}`;
}
