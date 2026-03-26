/**
 * API key management tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'list_api_keys',
    description: 'List your API keys.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    annotations: {
      title: 'List API Keys',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'create_api_key',
    description: 'Create a new API key.',
    inputSchema: {
      type: 'object',
      required: ['name'],
      properties: {
        name: { type: 'string', description: 'Human-readable name for the key' },
        scopes: {
          type: 'array',
          items: { type: 'string' },
          description: 'Permission scopes (e.g., ["gates:read", "passports:write"])',
        },
      },
    },
    annotations: {
      title: 'Create API Key',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'revoke_api_key',
    description: 'Revoke an API key.',
    inputSchema: {
      type: 'object',
      required: ['key_id'],
      properties: {
        key_id: { type: 'string', description: 'The API key ID to revoke' },
      },
    },
    annotations: {
      title: 'Revoke API Key',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  list_api_keys: async (api) => {
    return api.get('/api/users/api-keys');
  },

  create_api_key: async (api, args) => {
    const { name, scopes } = args as { name: string; scopes?: string[] };
    const body: Record<string, unknown> = { name };
    if (scopes !== undefined) body.scopes = scopes;
    return api.post('/api/users/api-keys', body);
  },

  revoke_api_key: async (api, args) => {
    const { key_id } = args as { key_id: string };
    return api.delete(`/api/users/api-keys/${key_id}`);
  },
};
