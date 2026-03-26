/**
 * CEL enforcement tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'enforce_action',
    description: 'Evaluate constraints and record an enforcement attestation via CEL.',
    inputSchema: {
      type: 'object',
      required: ['passport_id', 'action'],
      properties: {
        passport_id: { type: 'string', description: 'The passport ID' },
        action: { type: 'string', description: 'Action to enforce (e.g., "flights:book")' },
        target: { type: 'string', description: 'Optional target resource' },
        cost_cents: { type: 'number', description: 'Cost in cents for this action' },
        metadata: { type: 'object', description: 'Optional metadata' },
      },
    },
    annotations: {
      title: 'Enforce Action',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'list_enforcement_attestations',
    description: 'List enforcement attestations for a passport.',
    inputSchema: {
      type: 'object',
      required: ['passport_id'],
      properties: {
        passport_id: { type: 'string', description: 'The passport ID' },
        decision: { type: 'string', enum: ['PERMIT', 'BLOCK', 'SUSPEND'], description: 'Filter by decision' },
        limit: { type: 'number', description: 'Max results to return' },
      },
    },
    annotations: {
      title: 'List Enforcement Attestations',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'get_enforcement_attestation',
    description: 'Get a single enforcement attestation by ID.',
    inputSchema: {
      type: 'object',
      required: ['attestation_id'],
      properties: {
        attestation_id: { type: 'string', description: 'The enforcement attestation ID' },
      },
    },
    annotations: {
      title: 'Get Enforcement Attestation',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'verify_enforcement_attestation',
    description: 'Verify the cryptographic signature of an enforcement attestation.',
    inputSchema: {
      type: 'object',
      required: ['attestation_id'],
      properties: {
        attestation_id: { type: 'string', description: 'The enforcement attestation ID' },
      },
    },
    annotations: {
      title: 'Verify Enforcement Attestation',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  enforce_action: async (api, args) => {
    const { passport_id, action, target, cost_cents, metadata } = args as {
      passport_id: string; action: string; target?: string; cost_cents?: number; metadata?: unknown;
    };
    const body: Record<string, unknown> = { passport_id, action };
    if (target !== undefined) body.target = target;
    if (cost_cents !== undefined) body.cost_cents = cost_cents;
    if (metadata !== undefined) body.metadata = metadata;
    return api.post('/api/enforce', body);
  },

  list_enforcement_attestations: async (api, args) => {
    const { passport_id, decision, limit } = args as {
      passport_id: string; decision?: string; limit?: number;
    };
    return api.get(`/api/passports/${passport_id}/enforcement`, { decision, limit });
  },

  get_enforcement_attestation: async (api, args) => {
    const { attestation_id } = args as { attestation_id: string };
    return api.get(`/api/enforcement/${attestation_id}`);
  },

  verify_enforcement_attestation: async (api, args) => {
    const { attestation_id } = args as { attestation_id: string };
    return api.post(`/api/enforcement/${attestation_id}/verify`);
  },
};
