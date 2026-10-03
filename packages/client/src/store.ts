/**
 * What a task needs to be picked up again later: the grant and what it was issued for. The
 * grant is a credential; a store that persists it must protect it like one.
 */
export interface StoredTaskGrant {
  taskId: string;
  /** The task grant (`refresh_token`). */
  grant: string;
  /** The audience the task was issued for. */
  resource: string;
  /** The scope the task holds, space-separated. A refresh may ask for a subset, never more. */
  scope: string;
  /** When the task itself expires, ISO 8601. */
  taskExpiresAt: string;
}

/** Where task grants live between token refreshes and across restarts. */
export interface TaskGrantStore {
  save(record: StoredTaskGrant): Promise<void>;
  load(taskId: string): Promise<StoredTaskGrant | undefined>;
  remove(taskId: string): Promise<void>;
}

/** Grants held in this process only. The default; fine for a task that does not outlive the process. */
export class MemoryTaskGrantStore implements TaskGrantStore {
  readonly #records = new Map<string, StoredTaskGrant>();

  async save(record: StoredTaskGrant): Promise<void> {
    this.#records.set(record.taskId, { ...record });
  }

  async load(taskId: string): Promise<StoredTaskGrant | undefined> {
    const record = this.#records.get(taskId);
    return record ? { ...record } : undefined;
  }

  async remove(taskId: string): Promise<void> {
    this.#records.delete(taskId);
  }
}
