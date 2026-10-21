import http from "node:http";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  appendAuditRecord,
  reserveAction,
  stableStateKey,
  toolCallId,
} from "./runtime.js";

const PLUGIN_ID = "resource-hijack-llamafirewall-v5";

function requestJson(socketPath, path, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const request = http.request(
      {
        socketPath,
        path,
        method: "POST",
        timeout: timeoutMs,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          text += chunk;
        });
        response.on("end", () => {
          if ((response.statusCode ?? 500) >= 400) {
            reject(new Error(`scanner HTTP ${response.statusCode}: ${text.slice(0, 300)}`));
            return;
          }
          try {
            resolve(JSON.parse(text));
          } catch (error) {
            reject(new Error(`invalid scanner JSON: ${error.message}`));
          }
        });
      },
    );
    request.on("timeout", () => {
      request.destroy(new Error("scanner request timed out"));
    });
    request.on("error", reject);
    request.write(body);
    request.end();
  });
}

function contextFields(event, context, config) {
  return {
    run_id: event?.runId ?? context?.runId ?? null,
    session_id: context?.sessionId ?? null,
    session_key: context?.sessionKey ?? null,
    audit_tag: config.auditTag,
    attempt_id: config.attemptId,
    tool_call_id: toolCallId(event, context),
  };
}

function pluginAudit(config, event, context, eventType, extra = {}) {
  appendAuditRecord(config.fallbackAuditPath, {
    timestamp: Date.now() / 1000,
    record_type: "plugin",
    event_type: eventType,
    ...contextFields(event, context, config),
    ...extra,
  });
}

function failClosed(config, reason) {
  return config.failClosed ? { block: true, blockReason: reason } : undefined;
}

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "Resource Hijack LlamaFirewall",
  register(api) {
    const config = {
      socketPath: String(api.pluginConfig?.socketPath ?? ""),
      requestTimeoutMs: Number(api.pluginConfig?.requestTimeoutMs ?? 380000),
      failClosed: api.pluginConfig?.failClosed !== false,
      auditTag: String(api.pluginConfig?.auditTag ?? ""),
      attemptId: String(api.pluginConfig?.attemptId ?? ""),
      fallbackAuditPath: String(api.pluginConfig?.fallbackAuditPath ?? ""),
    };
    const runs = new Map();

    api.on(
      "before_agent_run",
      async (event, context) => {
        const key = stableStateKey(event, context);
        const prompt = String(event?.prompt ?? "");
        if (!key || !config.auditTag || !config.attemptId || !config.fallbackAuditPath) {
          const reason = "missing stable run key or LlamaFirewall audit configuration";
          api.logger.error(`[LlamaFirewall] ${reason}`);
          try {
            if (config.fallbackAuditPath) {
              pluginAudit(config, event, context, "state_error", { error: reason });
            }
          } catch (auditError) {
            api.logger.error(`[LlamaFirewall] fallback audit failed: ${auditError.message}`);
          }
          return {
            outcome: "block",
            reason,
            message: "[LlamaFirewall] Agent run blocked because audit identity is unavailable.",
          };
        }
        const state = { prompt, history: [], nextSequence: 0 };
        runs.set(key, state);
        try {
          pluginAudit(config, event, context, "run_start");
          await requestJson(
            config.socketPath,
            "/event",
            {
              event_type: "run_start",
              ...contextFields(event, context, config),
              prompt_present: prompt.length > 0,
            },
            Math.min(config.requestTimeoutMs, 10000),
          );
          pluginAudit(config, event, context, "run_start_confirmed");
          return { outcome: "pass" };
        } catch (error) {
          api.logger.error(`[LlamaFirewall] run-start audit failed: ${error.message}`);
          try {
            pluginAudit(config, event, context, "run_start_failed", {
              error: String(error.message),
            });
          } catch (auditError) {
            api.logger.error(`[LlamaFirewall] fallback audit failed: ${auditError.message}`);
          }
          if (config.failClosed) {
            return {
              outcome: "block",
              reason: "LlamaFirewall scanner service unavailable",
              message: "[LlamaFirewall] Agent run blocked because the scanner service is unavailable.",
            };
          }
          return { outcome: "pass" };
        }
      },
      { priority: 100, timeoutMs: 15000 },
    );

    api.on(
      "before_tool_call",
      async (event, context) => {
        const key = stableStateKey(event, context);
        const callId = toolCallId(event, context);
        if (!key || !callId) {
          const reason = "missing stable run key or toolCallId";
          api.logger.error(`[LlamaFirewall] ${reason}`);
          try {
            pluginAudit(config, event, context, "state_error", { error: reason });
          } catch (auditError) {
            api.logger.error(`[LlamaFirewall] fallback audit failed: ${auditError.message}`);
          }
          return failClosed(config, reason);
        }
        const state = runs.get(key);
        if (!state) {
          const reason = "missing before_agent_run state";
          api.logger.error(`[LlamaFirewall] ${reason}`);
          try {
            pluginAudit(config, event, context, "state_error", { error: reason });
          } catch (auditError) {
            api.logger.error(`[LlamaFirewall] fallback audit failed: ${auditError.message}`);
          }
          return failClosed(config, reason);
        }
        const action = {
          tool_name: String(event?.toolName ?? "unknown-tool"),
          params: event?.params ?? {},
        };
        const reserved = reserveAction(state, action);
        try {
          pluginAudit(config, event, context, "scan_started", {
            tool_name: action.tool_name,
            action_sequence: reserved.sequence,
            history_count: reserved.history.length,
          });
        } catch (error) {
          const reason = `fallback audit failure: ${error.message}`;
          api.logger.error(`[LlamaFirewall] ${reason}`);
          return failClosed(config, reason);
        }
        try {
          const result = await requestJson(
            config.socketPath,
            "/scan",
            {
              ...contextFields(event, context, config),
              user_prompt: state.prompt,
              history: reserved.history,
              action_sequence: reserved.sequence,
              action,
            },
            config.requestTimeoutMs,
          );
          pluginAudit(config, event, context, "scan_completed", {
            tool_name: action.tool_name,
            action_sequence: reserved.sequence,
            scanner_status: String(result.status ?? "unknown"),
            decision: String(result.decision ?? "unknown"),
            block: result.block === true,
          });
          if (result.status !== "success") {
            const reason = `scanner error: ${String(result.error ?? result.reason ?? "unknown")}`;
            return failClosed(config, reason);
          }
          if (result.block === true) {
            return {
              block: true,
              blockReason: `LlamaFirewall ${result.decision}: ${String(result.reason ?? "misaligned action").slice(0, 500)}`,
            };
          }
          return undefined;
        } catch (error) {
          api.logger.error(`[LlamaFirewall] scan failed: ${error.message}`);
          try {
            pluginAudit(config, event, context, "scan_failed", {
              tool_name: action.tool_name,
              action_sequence: reserved.sequence,
              error: String(error.message),
            });
          } catch (auditError) {
            api.logger.error(`[LlamaFirewall] fallback audit failed: ${auditError.message}`);
          }
          return failClosed(config, `LlamaFirewall scanner failure: ${error.message}`);
        }
      },
      { priority: 100, timeoutMs: 400000 },
    );

    api.on("agent_end", async (event, context) => {
      const key = stableStateKey(event, context);
      if (key) {
        runs.delete(key);
      }
    });
  },
});
