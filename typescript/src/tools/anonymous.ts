/**
 * Anonymous access tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'get_anonymous_policy',
    description: 'Get the anonymous access policy for a gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
      },
    },
    annotations: {
      title: 'Get Anonymous Policy',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'set_anonymous_policy',
    description: 'Configure anonymous access policy on a gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        enabled: { type: 'boolean', description: 'Enable or disable anonymous access' },
        allowed_actions: {
          type: 'array',
          items: { type: 'string' },
          description: 'Actions allowed for anonymous access',
        },
        blocked_actions: {
          type: 'array',
          items: { type: 'string' },
          description: 'Actions blocked for anonymous access',
        },
        rate_limit_per_minute: { type: 'number', description: 'Rate limit per minute for anonymous requests' },
        rate_limit_per_hour: { type: 'number', description: 'Rate limit per hour for anonymous requests' },
        read_only: { type: 'boolean', description: 'Restrict anonymous access to read-only actions' },
        upgrade_message: { type: 'string', description: 'Message shown when upgrade is needed' },
        upgrade_url: { type: 'string', description: 'URL for upgrading to authenticated access' },
      },
    },
    annotations: {
      title: 'Set Anonymous Policy',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: 'get_anonymous_log',
    description: 'Get the anonymous access audit log for a gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        limit: { type: 'number', description: 'Max results to return (default: 100)' },
      },
    },
    annotations: {
      title: 'Get Anonymous Log',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  get_anonymous_policy: async (api, args) => {
    const { gate_id } = args as { gate_id: string };
    return api.get(`/api/gates/${gate_id}/anonymous-policy`);
  },

  set_anonymous_policy: async (api, args) => {
    const { gate_id, ...body } = args as { gate_id: string } & Record<string, unknown>;
    return api.put(`/api/gates/${gate_id}/anonymous-policy`, body);
  },

  get_anonymous_log: async (api, args) => {
    const { gate_id, limit } = args as { gate_id: string; limit?: number };
    return api.get(`/api/gates/${gate_id}/anonymous-log`, { limit });
  },
};
