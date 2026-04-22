/**
 * Gate check and dry-run authorization tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'check_gate',
    description: 'Test a passport against a gate to preview the allow/deny decision.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'action'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID to check against' },
        action: { type: 'string', description: 'The action to check (e.g., "flights:search")' },
        passport_id: { type: 'string', description: 'The passport ID to check' },
        target: { type: 'string', description: 'Optional target resource' },
      },
    },
    annotations: {
      title: 'Check Gate',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: 'authorize_dry_run',
    description: 'Test authorization without executing. Simulates a full gate check.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'passport', 'requested_permission'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        passport: { type: 'object', description: 'Full passport object to test' },
        requested_permission: { type: 'string', description: 'Permission key to test' },
        requested_constraints: { type: 'object', description: 'Optional constraints to include in simulation' },
      },
    },
    annotations: {
      title: 'Authorize Dry Run',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  check_gate: async (api, args) => {
    const { gate_id, action, passport_id, target } = args as {
      gate_id: string; action: string; passport_id?: string; target?: string;
    };
    const body: Record<string, unknown> = { action };
    if (passport_id !== undefined) body.passport_id = passport_id;
    if (target !== undefined) body.target = target;
    return api.post(`/api/gates/${gate_id}/check`, body);
  },

  authorize_dry_run: async (api, args) => {
    const { gate_id, passport, requested_permission, requested_constraints } = args as {
      gate_id: string; passport: unknown; requested_permission: string; requested_constraints?: unknown;
    };
    const body: Record<string, unknown> = { gate_id, passport, requested_permission };
    if (requested_constraints !== undefined) body.requested_constraints = requested_constraints;
    return api.post('/api/authorize/dry-run', body);
  },
};
