import axios, { AxiosInstance } from 'axios';

export interface HypherClientOptions {
  gatewayUrl?: string;
  apiKey: string;
}

export class HypherSecurityClient {
  private client: AxiosInstance;

  constructor(options: HypherClientOptions) {
    this.client = axios.create({
      baseURL: options.gatewayUrl || 'http://localhost:3000',
      headers: {
        'Authorization': `Bearer ${options.apiKey}`,
        'Content-Type': 'application/json'
      }
    });
  }

  /**
   * Preflight check to verify if a tool call is safe before executing it locally.
   */
  async verifyToolCall(toolName: string, args: Record<string, any>): Promise<boolean> {
    try {
      const response = await this.client.post('/api/agent/tool-call', {
        tool: toolName,
        args: args
      });
      return response.status === 200;
    } catch (error: any) {
      if (error.response && error.response.status === 403) {
        console.warn(`[Hypher AI] Tool execution blocked: ${error.response.data.error}`);
        return false;
      }
      throw error;
    }
  }
}
