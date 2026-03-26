/**
 * Commerce tools — discovery, consumption, billing, SLA
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';

export const tools: Tool[] = [
  {
    name: 'discover_services',
    description: 'Discover services by capability (public, no auth required).',
    inputSchema: {
      type: 'object',
      required: ['capability'],
      properties: {
        capability: { type: 'string', description: 'Wildcard pattern (e.g., "flights:*", "weather:forecast")' },
        max_price_cents: { type: 'number', description: 'Maximum price in cents per call' },
        min_uptime_bp: { type: 'number', description: 'Minimum uptime in basis points (e.g., 9995 = 99.95%)' },
        max_response_time_ms: { type: 'number', description: 'Maximum response time in milliseconds' },
        pricing_model: { type: 'string', description: 'Filter by pricing model (per_call, per_minute, subscription)' },
        sort: { type: 'string', description: 'Sort order (e.g., "price_asc", "uptime_desc")' },
        limit: { type: 'number', description: 'Max results (default: 20)' },
        offset: { type: 'number', description: 'Pagination offset' },
      },
    },
    annotations: {
      title: 'Discover Services',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'issue_consumption_attestation',
    description: 'Issue a consumption attestation for bilateral metering.',
    inputSchema: {
      type: 'object',
      required: ['passport_id', 'gate_id', 'action', 'outcome'],
      properties: {
        passport_id: { type: 'string', description: 'The passport ID' },
        gate_id: { type: 'string', description: 'The gate ID' },
        action: { type: 'string', description: 'The action consumed (e.g., "flights:search")' },
        outcome: { type: 'string', enum: ['success', 'error', 'timeout', 'partial'], description: 'Outcome of the action' },
        quantity: { type: 'number', description: 'Number of units consumed (default: 1)' },
        agent_pop: { type: 'object', description: 'Agent proof-of-possession' },
        request_payload_hash: { type: 'string', description: 'SHA-256 hash of the request' },
        response_payload_hash: { type: 'string', description: 'SHA-256 hash of the response' },
        metadata: { type: 'object', description: 'Optional metadata' },
      },
    },
    annotations: {
      title: 'Issue Consumption Attestation',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'generate_settlement',
    description: 'Generate a billing settlement for a period.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'period_type', 'period_start', 'period_end'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        period_type: { type: 'string', enum: ['daily', 'weekly', 'monthly'], description: 'Settlement period type' },
        period_start: { type: 'string', description: 'Period start date (YYYY-MM-DD)' },
        period_end: { type: 'string', description: 'Period end date (YYYY-MM-DD)' },
        agent_id: { type: 'string', description: 'Optional: settle for a specific agent' },
      },
    },
    annotations: {
      title: 'Generate Settlement',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'list_settlements',
    description: 'List settlement summaries.',
    inputSchema: {
      type: 'object',
      properties: {
        gate_id: { type: 'string', description: 'Filter by gate ID' },
        agent_id: { type: 'string', description: 'Filter by agent ID' },
        period_type: { type: 'string', description: 'Filter by period type' },
        status: { type: 'string', description: 'Filter by status (e.g., "pending", "invoiced")' },
        from_date: { type: 'string', description: 'Filter from date (YYYY-MM-DD)' },
        to_date: { type: 'string', description: 'Filter to date (YYYY-MM-DD)' },
        limit: { type: 'number', description: 'Max results (default: 20)' },
        offset: { type: 'number', description: 'Pagination offset' },
      },
    },
    annotations: {
      title: 'List Settlements',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'get_settlement',
    description: 'Get a settlement by ID.',
    inputSchema: {
      type: 'object',
      required: ['settlement_id'],
      properties: {
        settlement_id: { type: 'string', description: 'The settlement ID' },
      },
    },
    annotations: {
      title: 'Get Settlement',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
  {
    name: 'update_settlement_status',
    description: 'Transition a settlement to a new status.',
    inputSchema: {
      type: 'object',
      required: ['settlement_id', 'status'],
      properties: {
        settlement_id: { type: 'string', description: 'The settlement ID' },
        status: { type: 'string', description: 'New status (e.g., "invoiced", "paid", "disputed")' },
      },
    },
    annotations: {
      title: 'Update Settlement Status',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: 'get_sla_compliance',
    description: 'Get SLA compliance metrics for a gate.',
    inputSchema: {
      type: 'object',
      required: ['gate_id', 'period_start', 'period_end'],
      properties: {
        gate_id: { type: 'string', description: 'The gate ID' },
        period_start: { type: 'string', description: 'Period start (YYYY-MM-DD)' },
        period_end: { type: 'string', description: 'Period end (YYYY-MM-DD)' },
        permission_key: { type: 'string', description: 'Filter by permission key' },
      },
    },
    annotations: {
      title: 'Get SLA Compliance',
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
];

export const handlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  discover_services: async (api, args) => {
    const { capability, max_price_cents, min_uptime_bp, max_response_time_ms, pricing_model, sort, limit, offset } = args as {
      capability: string; max_price_cents?: number; min_uptime_bp?: number;
      max_response_time_ms?: number; pricing_model?: string; sort?: string;
      limit?: number; offset?: number;
    };
    return api.get('/api/discover', {
      capability, max_price_cents, min_uptime_bp, max_response_time_ms, pricing_model, sort, limit, offset,
    });
  },

  issue_consumption_attestation: async (api, args) => {
    const { passport_id, gate_id, action, outcome, quantity, agent_pop, request_payload_hash, response_payload_hash, metadata } = args as {
      passport_id: string; gate_id: string; action: string; outcome: string;
      quantity?: number; agent_pop?: unknown; request_payload_hash?: string;
      response_payload_hash?: string; metadata?: unknown;
    };
    const body: Record<string, unknown> = { passport_id, gate_id, action, outcome, quantity: quantity ?? 1 };
    if (agent_pop !== undefined) body.agent_pop = agent_pop;
    if (request_payload_hash !== undefined) body.request_payload_hash = request_payload_hash;
    if (response_payload_hash !== undefined) body.response_payload_hash = response_payload_hash;
    if (metadata !== undefined) body.metadata = metadata;
    return api.post('/api/consume', body);
  },

  generate_settlement: async (api, args) => {
    const { gate_id, period_type, period_start, period_end, agent_id } = args as {
      gate_id: string; period_type: string; period_start: string; period_end: string; agent_id?: string;
    };
    const body: Record<string, unknown> = { gate_id, period_type, period_start, period_end };
    if (agent_id !== undefined) body.agent_id = agent_id;
    return api.post('/api/billing', body);
  },

  list_settlements: async (api, args) => {
    const { gate_id, agent_id, period_type, status, from_date, to_date, limit, offset } = args as {
      gate_id?: string; agent_id?: string; period_type?: string; status?: string;
      from_date?: string; to_date?: string; limit?: number; offset?: number;
    };
    return api.get('/api/billing', {
      gate_id, agent_id, period_type, status, from: from_date, to: to_date, limit, offset,
    });
  },

  get_settlement: async (api, args) => {
    const { settlement_id } = args as { settlement_id: string };
    return api.get(`/api/billing/${settlement_id}`);
  },

  update_settlement_status: async (api, args) => {
    const { settlement_id, status } = args as { settlement_id: string; status: string };
    return api.post(`/api/billing/${settlement_id}/status`, { status });
  },

  get_sla_compliance: async (api, args) => {
    const { gate_id, period_start, period_end, permission_key } = args as {
      gate_id: string; period_start: string; period_end: string; permission_key?: string;
    };
    return api.get(`/api/gates/${gate_id}/sla`, { period_start, period_end, permission_key });
  },
};
