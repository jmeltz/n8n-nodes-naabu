import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { writeFile, unlink } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';

const execFileAsync = promisify(execFile);

export class Naabu implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Naabu',
		name: 'naabu',
		icon: 'file:naabu.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Port scanning with naabu',
		defaults: {
			name: 'Naabu',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Scan',
						value: 'scan',
						description: 'Scan ports on target hosts',
						action: 'Scan ports on target hosts',
					},
				],
				default: 'scan',
			},

			// --- Target ---
			{
				displayName: 'Target',
				name: 'target',
				type: 'string',
				default: '',
				required: true,
				placeholder: 'e.g. example.com or 192.168.1.1',
				description: 'Host(s) to scan. Comma-separated for multiple targets.',
				displayOptions: {
					show: { operation: ['scan'] },
				},
			},

			// --- Port selection ---
			{
				displayName: 'Port Selection',
				name: 'portSelection',
				type: 'options',
				options: [
					{
						name: 'Top Ports',
						value: 'topPorts',
						description: 'Scan top N common ports',
					},
					{
						name: 'Specific Ports',
						value: 'specificPorts',
						description: 'Specify exact ports or ranges',
					},
					{
						name: 'Full Scan',
						value: 'full',
						description: 'Scan all 65535 ports',
					},
				],
				default: 'topPorts',
				displayOptions: {
					show: { operation: ['scan'] },
				},
			},
			{
				displayName: 'Top Ports Count',
				name: 'topPortsCount',
				type: 'options',
				options: [
					{ name: '100', value: '100' },
					{ name: '1000', value: '1000' },
				],
				default: '100',
				displayOptions: {
					show: { operation: ['scan'], portSelection: ['topPorts'] },
				},
			},
			{
				displayName: 'Ports',
				name: 'ports',
				type: 'string',
				default: '',
				placeholder: 'e.g. 80,443,8080-8090',
				description: 'Comma-separated ports or ranges',
				displayOptions: {
					show: { operation: ['scan'], portSelection: ['specificPorts'] },
				},
			},

			// --- Advanced Options ---
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				displayOptions: {
					show: { operation: ['scan'] },
				},
				options: [
					{
						displayName: 'Exclude Ports',
						name: 'excludePorts',
						type: 'string',
						default: '',
						placeholder: 'e.g. 22,3389',
						description: 'Ports to exclude from the scan',
					},
					{
						displayName: 'Exclude Hosts',
						name: 'excludeHosts',
						type: 'string',
						default: '',
						placeholder: 'e.g. 192.168.1.1,10.0.0.0/8',
						description: 'Hosts to exclude from the scan',
					},
					{
						displayName: 'Scan Type',
						name: 'scanType',
						type: 'options',
						options: [
							{ name: 'CONNECT (default)', value: 'c' },
							{ name: 'SYN (requires root)', value: 's' },
						],
						default: 'c',
						description: 'Type of port scan to perform',
					},
					{
						displayName: 'Rate',
						name: 'rate',
						type: 'number',
						default: 1000,
						description: 'Packets per second',
					},
					{
						displayName: 'Threads',
						name: 'threads',
						type: 'number',
						default: 25,
						description: 'Number of worker threads',
					},
					{
						displayName: 'Retries',
						name: 'retries',
						type: 'number',
						default: 3,
						description: 'Number of retries for port scan',
					},
					{
						displayName: 'Timeout (ms)',
						name: 'timeout',
						type: 'number',
						default: 1000,
						description: 'Timeout in milliseconds per port',
					},
					{
						displayName: 'Exclude CDN',
						name: 'excludeCdn',
						type: 'boolean',
						default: false,
						description: 'Whether to skip full port scan for CDN/WAF (only scan 80,443)',
					},
					{
						displayName: 'Display CDN',
						name: 'displayCdn',
						type: 'boolean',
						default: false,
						description: 'Whether to display CDN information in results',
					},
					{
						displayName: 'Nmap Command',
						name: 'nmapCli',
						type: 'string',
						default: '',
						placeholder: 'e.g. nmap -sV -Pn',
						description: 'Run nmap command on discovered ports',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const target = this.getNodeParameter('target', i) as string;
				const portSelection = this.getNodeParameter('portSelection', i) as string;
				const options = this.getNodeParameter('options', i, {}) as {
					excludePorts?: string;
					excludeHosts?: string;
					scanType?: string;
					rate?: number;
					threads?: number;
					retries?: number;
					timeout?: number;
					excludeCdn?: boolean;
					displayCdn?: boolean;
					nmapCli?: string;
				};

				const args: string[] = ['-json'];

				// Target - use temp file for multiple targets
				const targets = target.split(',').map((t) => t.trim()).filter(Boolean);
				let tempFile: string | undefined;

				if (targets.length === 1) {
					args.push('-host', targets[0]);
				} else {
					tempFile = join(tmpdir(), `naabu-targets-${randomBytes(6).toString('hex')}.txt`);
					await writeFile(tempFile, targets.join('\n'));
					args.push('-l', tempFile);
				}

				// Port selection
				if (portSelection === 'topPorts') {
					const count = this.getNodeParameter('topPortsCount', i) as string;
					args.push('-top-ports', count);
				} else if (portSelection === 'specificPorts') {
					const ports = this.getNodeParameter('ports', i) as string;
					if (ports) {
						args.push('-p', ports);
					}
				} else if (portSelection === 'full') {
					args.push('-top-ports', 'full');
				}

				// Options
				if (options.excludePorts) {
					args.push('-ep', options.excludePorts);
				}
				if (options.excludeHosts) {
					args.push('-eh', options.excludeHosts);
				}
				if (options.scanType) {
					args.push('-s', options.scanType);
				}
				if (options.rate !== undefined) {
					args.push('-rate', String(options.rate));
				}
				if (options.threads !== undefined) {
					args.push('-c', String(options.threads));
				}
				if (options.retries !== undefined) {
					args.push('-retries', String(options.retries));
				}
				if (options.timeout !== undefined) {
					args.push('-timeout', String(options.timeout));
				}
				if (options.excludeCdn) {
					args.push('-ec');
				}
				if (options.displayCdn) {
					args.push('-cdn');
				}
				if (options.nmapCli) {
					args.push('-nmap-cli', options.nmapCli);
				}

				// Disable update check
				args.push('-duc');

				let stdout: string;
				try {
					const result = await execFileAsync('naabu', args, {
						timeout: 600000, // 10 minute max
						maxBuffer: 50 * 1024 * 1024,
					});
					stdout = result.stdout;
				} finally {
					if (tempFile) {
						await unlink(tempFile).catch(() => {});
					}
				}

				// Parse JSON lines output
				const lines = stdout.trim().split('\n').filter(Boolean);
				if (lines.length === 0) {
					returnData.push({
						json: { target, openPorts: [], count: 0 },
						pairedItem: { item: i },
					});
					continue;
				}

				for (const line of lines) {
					try {
						const parsed = JSON.parse(line);
						returnData.push({
							json: parsed,
							pairedItem: { item: i },
						});
					} catch {
						// skip non-JSON lines (naabu sometimes outputs status messages)
					}
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: (error as Error).message },
						pairedItem: { item: i },
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), error as Error, {
					itemIndex: i,
					description: 'Make sure naabu is installed and available in PATH. Install from https://github.com/projectdiscovery/naabu',
				});
			}
		}

		return [returnData];
	}
}
