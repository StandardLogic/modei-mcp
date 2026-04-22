/**
 * Attestation tools - audit log access
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'list_attestations',
    description: 'List attestations (audit log entries) for a gate. Shows what agents did and whether actions were allowed.',
    inputSchema: {
      type: 'object',
      required: ['gate_id'],
      properties: {
        gate_id: {
          type: 'string',
          description: 'The gate ID',
        },
        passport_id: {
          type: 'string',
          description: 'Filter by passport ID',
        },
        agent_id: {
          type: 'string',
          description: 'Filter by agent ID',
        },
        permission: {
          type: 'string',
          description: 'Filter by permission key',
        },
        since: {
          type: 'string',
          description: 'ISO timestamp - only return attestations after this time',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default: 100, max: 1000)',
        },
      },
    },
    annotations: {
      title: 'List Attestations',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'record_attestation',
    description: 'Record a new attestation. Usually called automatically by MCP servers, but can be called manually for testing.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'passport_id', 'agent_id', 'permission', 'tool_name', 'result'],
      properties: {
        gate_id: {
          type: 'string',
          description: 'The gate ID',
        },
        passport_id: {
          type: 'string',
          description: 'The passport that was used',
        },
        agent_id: {
          type: 'string',
          description: 'The agent that made the request',
        },
        permission: {
          type: 'string',
          description: 'The permission that was checked',
        },
        tool_name: {
          type: 'string',
          description: 'Name of the tool that was called',
        },
        result: {
          type: 'string',
          enum: ['allowed', 'denied'],
          description: 'Whether the action was allowed or denied',
        },
        denial_code: {
          type: 'string',
          description: 'If denied, the denial code',
        },
        input_hash: {
          type: 'string',
          description: 'SHA-256 hash of the input (for privacy)',
        },
        output_hash: {
          type: 'string',
          description: 'SHA-256 hash of the output (for privacy)',
        },
        constraints_used: {
          type: 'object',
          description: 'Constraints that were checked',
        },
        execution_ms: {
          type: 'number',
          description: 'How long the tool call took in milliseconds',
        },
        metadata: {
          type: 'object',
          description: 'Additional metadata',
        },
      },
    },
    annotations: {
      title: 'Record Attestation',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  list_attestations: async (api: ApiClient, args: Record<string, unknown>) => {
    const { gate_id, passport_id, agent_id, permission, since, limit } = args as {
      gate_id: string;
      passport_id?: string;
      agent_id?: string;
      permission?: string;
      since?: string;
      limit?: number;
    };

    const params = new URLSearchParams();
    if (passport_id) params.set('passport_id', passport_id);
    if (agent_id) params.set('agent_id', agent_id);
    if (permission) params.set('permission', permission);
    if (since) params.set('since', since);
    if (limit) params.set('limit', String(limit));

    const query = params.toString();
    return api.get(`/api/gates/${gate_id}/attestations${query ? `?${query}` : ''}`);
  },

  record_attestation: async (api: ApiClient, args: Record<string, unknown>) => {
    const { gate_id, ...body } = args as { gate_id: string } & Record<string, unknown>;
    return api.post(`/api/gates/${gate_id}/attestations`, body);
  },
};
