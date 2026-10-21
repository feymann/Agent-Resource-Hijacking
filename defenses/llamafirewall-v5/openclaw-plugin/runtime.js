import { closeSync, fsyncSync, openSync, writeSync } from "node:fs";

function nonEmptyString(value) {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function stableStateKey(event, context) {
  return (
    nonEmptyString(event?.runId) ??
    nonEmptyString(context?.runId) ??
    nonEmptyString(context?.sessionId) ??
    nonEmptyString(context?.sessionKey)
  );
}

export function toolCallId(event, context) {
  return nonEmptyString(event?.toolCallId) ?? nonEmptyString(context?.toolCallId);
}

export function reserveAction(state, action) {
  const sequence = state.nextSequence;
  state.nextSequence += 1;
  const history = state.history.map((entry) => entry.action);
  state.history.push({ sequence, action });
  return { sequence, history };
}

export function appendAuditRecord(path, record) {
  let descriptor;
  try {
    descriptor = openSync(path, "a");
    writeSync(descriptor, `${JSON.stringify(record)}\n`, null, "utf8");
    fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
  }
}
