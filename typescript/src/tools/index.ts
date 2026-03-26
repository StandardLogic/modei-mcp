/**
 * Tool registry - exports all available tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ApiClient } from '../api-client.js';
import { tools as gatesTools, handlers as gatesHandlers } from './gates.js';
import { tools as passportsTools, handlers as passportsHandlers } from './passports.js';
import { tools as attestationsTools, handlers as attestationsHandlers } from './attestations.js';
import { tools as catalogsTools, handlers as catalogsHandlers } from './catalogs.js';
import { tools as checkTools, handlers as checkHandlers } from './check.js';
import { tools as constraintsTools, handlers as constraintsHandlers } from './constraints.js';
import { tools as enforcementTools, handlers as enforcementHandlers } from './enforcement.js';
import { tools as anonymousTools, handlers as anonymousHandlers } from './anonymous.js';
import { tools as stateTools, handlers as stateHandlers } from './state.js';
import { tools as commerceTools, handlers as commerceHandlers } from './commerce.js';
import { tools as apiKeysTools, handlers as apiKeysHandlers } from './api-keys.js';

export const allTools: Tool[] = [
  ...gatesTools,
  ...passportsTools,
  ...attestationsTools,
  ...catalogsTools,
  ...checkTools,
  ...constraintsTools,
  ...enforcementTools,
  ...anonymousTools,
  ...stateTools,
  ...commerceTools,
  ...apiKeysTools,
];

const allHandlers: Record<string, (api: ApiClient, args: Record<string, unknown>) => Promise<unknown>> = {
  ...gatesHandlers,
  ...passportsHandlers,
  ...attestationsHandlers,
  ...catalogsHandlers,
  ...checkHandlers,
  ...constraintsHandlers,
  ...enforcementHandlers,
  ...anonymousHandlers,
  ...stateHandlers,
  ...commerceHandlers,
  ...apiKeysHandlers,
};

export async function handleToolCall(
  api: ApiClient,
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  const handler = allHandlers[name];
  if (!handler) {
    throw new Error(`Unknown tool: ${name}`);
  }
  return handler(api, args);
}
