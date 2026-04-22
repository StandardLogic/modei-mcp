/**
 * Permission catalog tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'get_catalog',
    description: 'Get the active draft permission catalog for a gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
      },
    },
    annotations: {
      title: 'Get Catalog',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'create_catalog',
    description: 'Create or update the permission catalog for a gate. Defines what permissions agents can request.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'permissions'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        version: { type: 'string', description: 'Semver version (e.g., "1.0.0")' },
        catalog_name: { type: 'string', description: 'Human-readable name' },
        description: { type: 'string', description: 'Optional description' },
        permissions: {
          type: 'array',
          description: 'Permission definitions',
          items: {
            type: 'object',
            required: ['permission_key', 'display_name', 'description', 'risk_level', 'min_trust_level'],
            properties: {
              permission_key: { type: 'string' },
              display_name: { type: 'string' },
              description: { type: 'string' },
              risk_level: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
              min_trust_level: { type: 'number', enum: [1, 2, 3] },
              constraints: { type: 'object' },
            },
          },
        },
        is_active: { type: 'boolean', description: 'Whether this catalog is active (default: true)' },
      },
    },
    annotations: {
      title: 'Create Catalog',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'publish_catalog',
    description: 'Build, sign, and atomically publish a catalog snapshot.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        change_summary: { type: 'string', description: 'Summary of changes in this version' },
        effective_at: { type: 'string', description: 'ISO timestamp when this version becomes effective' },
      },
    },
    annotations: {
      title: 'Publish Catalog',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'list_catalog_versions',
    description: 'List all published catalog versions (metadata only).',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
      },
    },
    annotations: {
      title: 'List Catalog Versions',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'get_catalog_version',
    description: 'Get a specific published catalog version.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'version'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        version: { type: 'number', description: 'Version number to retrieve' },
      },
    },
    annotations: {
      title: 'Get Catalog Version',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'get_catalog_impact',
    description: 'Get impact analysis for pending catalog changes.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
      },
    },
    annotations: {
      title: 'Get Catalog Impact',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  get_catalog: async (api, args) => {
    const { gate_id } = args as { gate_id: string };
    return api.get(`/api/gates/${gate_id}/catalog`);
  },

  create_catalog: async (api, args) => {
    const { gate_id, ...body } = args as { gate_id: string } & Record<string, unknown>;
    return api.post(`/api/gates/${gate_id}/catalog`, body);
  },

  publish_catalog: async (api, args) => {
    const { gate_id, change_summary, effective_at } = args as {
      gate_id: string; change_summary?: string; effective_at?: string;
    };
    const body: Record<string, unknown> = {};
    if (change_summary !== undefined) body.change_summary = change_summary;
    if (effective_at !== undefined) body.effective_at = effective_at;
    return api.post(`/api/gates/${gate_id}/catalog/publish`, body);
  },

  list_catalog_versions: async (api, args) => {
    const { gate_id } = args as { gate_id: string };
    return api.get(`/api/gates/${gate_id}/catalog/versions`);
  },

  get_catalog_version: async (api, args) => {
    const { gate_id, version } = args as { gate_id: string; version: number };
    return api.get(`/api/gates/${gate_id}/catalog/${version}`);
  },

  get_catalog_impact: async (api, args) => {
    const { gate_id } = args as { gate_id: string };
    return api.get(`/api/gates/${gate_id}/catalog/impact`);
  },
};
