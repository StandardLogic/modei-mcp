/**
 * Gate management tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'list_gates',
    description: 'List all gates you own. Gates are permission enforcement points that protect your tools.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    annotations: {
      title: 'List Gates',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'get_gate',
    description: 'Get details for a specific gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: {
          type: 'string',
          description: 'The full gate ID (e.g., "gate_acme-travel")',
        },
      },
    },
    annotations: {
      title: 'Get Gate',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'create_gate',
    description: 'Create a new gate. A gate defines what permissions exist and enforces access control for your tools.',
    inputSchema: {
      type: 'object',
      required: ['name', 'gate_id', 'profile'],
      properties: {
        name: {
          type: 'string',
          description: 'Human-readable name for the gate (e.g., "Acme Travel API")',
        },
        gate_id: {
          type: 'string',
          description: 'Unique identifier suffix. Will be prefixed with "gate_". Use lowercase, numbers, hyphens (e.g., "acme-travel")',
        },
        description: {
          type: 'string',
          description: 'Optional description of what this gate protects',
        },
        profile: {
          type: 'string',
          enum: ['L1', 'L2', 'L3'],
          description: 'Trust profile: L1 (dev/test), L2 (production), L3 (financial, requires proof-of-possession)',
        },
        allow_self_issued: {
          type: 'boolean',
          description: 'For L1 only: allow self-issued passports (default: false)',
        },
      },
    },
    annotations: {
      title: 'Create Gate',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'update_gate',
    description: 'Update settings for an existing gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: {
          type: 'string',
          description: 'The full gate ID (e.g., "gate_acme-travel")',
        },
        name: { type: 'string', description: 'New name' },
        description: { type: 'string', description: 'New description' },
        profile: { type: 'string', enum: ['L1', 'L2', 'L3'], description: 'New trust profile' },
        allow_self_issued: { type: 'boolean', description: 'Allow self-issued passports (L1 only)' },
      },
    },
    annotations: {
      title: 'Update Gate',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: 'delete_gate',
    description: 'Delete (archive) a gate. This will deactivate all signing keys.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: {
          type: 'string',
          description: 'The full gate ID to delete',
        },
      },
    },
    annotations: {
      title: 'Delete Gate',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  list_gates: async (api) => {
    return api.get('/api/gates');
  },

  get_gate: async (api, args) => {
    const { gate_id } = args as { gate_id: string };
    return api.get(`/api/gates/${gate_id}`);
  },

  create_gate: async (api, args) => {
    const { name, gate_id, description, profile, allow_self_issued } = args as {
      name: string; gate_id: string; description?: string; profile: string; allow_self_issued?: boolean;
    };
    return api.post('/api/gates', { name, gate_id, description, profile, allow_self_issued });
  },

  update_gate: async (api, args) => {
    const { gate_id, ...updates } = args as { gate_id: string } & Record<string, unknown>;
    return api.patch(`/api/gates/${gate_id}`, updates);
  },

  delete_gate: async (api, args) => {
    const { gate_id } = args as { gate_id: string };
    return api.delete(`/api/gates/${gate_id}`);
  },
};
