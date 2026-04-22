/**
 * Passport management tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'list_passports',
    description: 'List all active passports for a gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: {
          type: 'string',
          description: 'The gate ID to list passports for',
        },
        limit: { type: 'number', description: 'Max results to return (default: 100)' },
      },
    },
    annotations: {
      title: 'List Passports',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'get_passport',
    description: 'Get details for a specific passport.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'passport_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        passport_id: { type: 'string', description: 'The passport ID' },
      },
    },
    annotations: {
      title: 'Get Passport',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'issue_passport',
    description: 'Issue a new passport to an agent. The passport grants the agent specific permissions for this gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'agent_id', 'permissions'],
      properties: {
        gate_id: {
          type: 'string',
          description: 'The gate ID to issue passport for',
        },
        agent_id: {
          type: 'string',
          description: 'Identifier for the agent receiving the passport',
        },
        agent_name: {
          type: 'string',
          description: 'Human-readable name for the agent',
        },
        agent_public_key: {
          type: 'string',
          description: 'Agent public key (base64) for proof-of-possession',
        },
        permissions: {
          type: 'array',
          items: { type: 'string' },
          description: 'Permission keys to grant (e.g., ["flights:search", "flights:book"])',
        },
        constraints: {
          type: 'object',
          description: 'Optional constraints (e.g., { "core:cost:max_per_action": 100000 })',
        },
        expires_in_seconds: {
          type: 'number',
          description: 'How long until passport expires (default: 3600 = 1 hour)',
        },
        expires_in: {
          type: 'string',
          description: 'Human-friendly expiry (e.g., "7d", "24h")',
        },
        metadata: {
          type: 'object',
          description: 'Optional metadata to attach to the passport',
        },
      },
    },
    annotations: {
      title: 'Issue Passport',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'revoke_passport',
    description: 'Revoke a passport immediately. The agent will no longer be able to use it.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'passport_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        passport_id: { type: 'string', description: 'The passport ID to revoke' },
      },
    },
    annotations: {
      title: 'Revoke Passport',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: 'reissue_passport',
    description: 'Re-issue a passport pinned to a newer catalog version.',
    inputSchema: {
      type: 'object',
      required: ['passport_id'],
      properties: {
        passport_id: {
          type: 'string',
          description: 'The passport ID to reissue',
        },
        accept_catalog_version: {
          type: 'number',
          description: 'Catalog version to pin the reissued passport to',
        },
      },
    },
    annotations: {
      title: 'Reissue Passport',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  list_passports: async (api, args) => {
    const { gate_id, limit } = args as { gate_id: string; limit?: number };
    return api.get(`/api/gates/${gate_id}/passports`, { limit });
  },

  get_passport: async (api, args) => {
    const { gate_id, passport_id } = args as { gate_id: string; passport_id: string };
    return api.get(`/api/gates/${gate_id}/passports/${passport_id}`);
  },

  issue_passport: async (api, args) => {
    const { gate_id, ...body } = args as { gate_id: string } & Record<string, unknown>;
    return api.post(`/api/gates/${gate_id}/passports`, body);
  },

  revoke_passport: async (api, args) => {
    const { gate_id, passport_id } = args as { gate_id: string; passport_id: string };
    return api.delete(`/api/gates/${gate_id}/passports/${passport_id}`);
  },

  reissue_passport: async (api, args) => {
    const { passport_id, accept_catalog_version } = args as {
      passport_id: string; accept_catalog_version?: number;
    };
    const body: Record<string, unknown> = {};
    if (accept_catalog_version !== undefined) body.accept_catalog_version = accept_catalog_version;
    return api.post(`/api/passports/${passport_id}/reissue`, body);
  },
};
