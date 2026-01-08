import {
    IExecuteFunctions,
    INodeExecutionData,
    INodeType,
    INodeTypeDescription,
    NodeOperationError,
} from 'n8n-workflow';

export class Antijection implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'Antijection',
        name: 'antijection',
        icon: 'file:../../icons/antijection.svg',
        group: ['transform'],
        version: 1,
        subtitle: '={{$parameter["detectionMethod"]}}',
        description: 'Detect prompt injection and safety issues',
        defaults: {
            name: 'Antijection',
        },
        usableAsTool: true,
        inputs: ['main'],
        outputs: ['main'],
        credentials: [
            {
                name: 'antijectionApi',
                required: true,
            },
        ],
        properties: [
            {
                displayName: 'Prompt',
                name: 'prompt',
                type: 'string',
                default: '',
                placeholder: 'Enter the user prompt or AI input to analyze...',
                description: 'The text prompt to analyze for injections and safety risks (1-10,000 characters). Prompts with risk_score ≥ 50 should be blocked.',
                required: true,
                typeOptions: {
                    rows: 5,
                },
            },
            {
                displayName: 'Detection Method',
                name: 'detectionMethod',
                type: 'options',
                options: [
                    {
                        name: 'Injection Guard (Fast)',
                        value: 'INJECTION_GUARD',
                        description: 'Fast injection detection (English only)',
                    },
                    {
                        name: 'Injection Guard Multi (Multilingual)',
                        value: 'INJECTION_GUARD_MULTI',
                        description: 'Multilingual injection detection',
                    },
                    {
                        name: 'Safety Guard (Comprehensive)',
                        value: 'SAFETY_GUARD',
                        description: 'Comprehensive safety analysis',
                    },
                ],
                default: 'INJECTION_GUARD_MULTI',
                description: 'The detection model/method to use',
            },
            {
                displayName: 'Rule Settings',
                name: 'ruleSettings',
                placeholder: 'Add Rule Settings',
                type: 'collection',
                default: {},
                description: 'Configure heuristic detection rules for fine-tuned protection',
                options: [
                    {
                        displayName: 'Enabled',
                        name: 'enabled',
                        type: 'boolean',
                        default: true,
                        description: 'Whether to enable heuristic rule-based detection',
                    },
                    {
                        displayName: 'Disabled Categories',
                        name: 'disabledCategories',
                        type: 'multiOptions',
                        default: [],
                        description: 'Select rule categories to disable. Useful for coding assistants that need to process SQL or shell commands.',
                        options: [
                            {
                                name: 'Command Injection',
                                value: 'command_injection',
                                description: 'Shell command execution attempts',
                            },
                            {
                                name: 'Emojis',
                                value: 'emojis',
                                description: 'Suspicious or excessive use of emojis',
                            },
                            {
                                name: 'Encoded Attacks',
                                value: 'encoded_attacks',
                                description: 'Base64, Hex, or Unicode encoding tricks',
                            },
                            {
                                name: 'Fuzzy Matches',
                                value: 'fuzzy_matches',
                                description: 'Common misspellings of attack keywords',
                            },
                            {
                                name: 'Ignore Instructions',
                                value: 'ignore_instructions',
                                description: 'Direct attempts to override system prompts',
                            },
                            {
                                name: 'Many Shot',
                                value: 'many_shot',
                                description: 'Overloading context with fake Q&A',
                            },
                            {
                                name: 'Path Traversal',
                                value: 'path_traversal',
                                description: 'File system traversal attempts',
                            },
                            {
                                name: 'Prompt Extraction',
                                value: 'prompt_extraction',
                                description: 'Attempts to leak the system prompt',
                            },
                            {
                                name: 'Repetition Attacks',
                                value: 'repetition_attacks',
                                description: 'Excessive or interspersed repetition',
                            },
                            {
                                name: 'Role Hijacking',
                                value: 'role_hijacking',
                                description: 'Forcing the AI into a specific persona',
                            },
                            {
                                name: 'SQL Injection',
                                value: 'sql_injection',
                                description: 'Common SQL injection patterns',
                            },
                            {
                                name: 'System Override',
                                value: 'system_override',
                                description: 'Attempts to toggle developer/admin modes',
                            },
                            {
                                name: 'Unusual Punctuation',
                                value: 'unusual_punctuation',
                                description: 'Abnormal clusters of special characters',
                            },
                            {
                                name: 'XSS Patterns',
                                value: 'xss_patterns',
                                description: 'Script injection and XSS vectors',
                            },
                        ],
                    },
                    {
                        displayName: 'Blocked Keywords',
                        name: 'blockedKeywords',
                        type: 'string',
                        typeOptions: {
                            rows: 4,
                        },
                        default: '',
                        placeholder: 'internal_project_name\n<special_token>\n\\b(secret|key)\\b',
                        description: 'Custom keywords or regex patterns to block (one per line). Supports Python-style regex.',
                    },
                ],
            },
        ],
    };

    async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
        const items = this.getInputData();
        const returnData: INodeExecutionData[] = [];
        const credentials = await this.getCredentials('antijectionApi');

        const baseUrl = (credentials.baseUrl as string).replace(/\/$/, '');
        const apiKey = credentials.apiKey as string;

        for (let i = 0; i < items.length; i++) {
            try {
                const prompt = this.getNodeParameter('prompt', i) as string;
                const detectionMethod = this.getNodeParameter('detectionMethod', i) as string;
                const ruleSettings = this.getNodeParameter('ruleSettings', i) as {
                    enabled?: boolean;
                    disabledCategories?: string[];
                    blockedKeywords?: string;
                };

                // Validate prompt length
                if (!prompt || prompt.trim().length === 0) {
                    throw new NodeOperationError(
                        this.getNode(),
                        'Prompt cannot be empty',
                        { itemIndex: i }
                    );
                }

                if (prompt.length > 10000) {
                    throw new NodeOperationError(
                        this.getNode(),
                        `Prompt is too long (${prompt.length} characters). Maximum allowed is 10,000 characters.`,
                        { itemIndex: i }
                    );
                }

                const payload: {
                    prompt: string;
                    detection_method: string;
                    rule_settings?: {
                        enabled: boolean;
                        disabled_categories: string[];
                        blocked_keywords: string[];
                    };
                } = {
                    prompt,
                    detection_method: detectionMethod,
                };

                if (ruleSettings) {
                    // Handle blocked keywords - split by newlines
                    const blockedKeywords = ruleSettings.blockedKeywords
                        ? ruleSettings.blockedKeywords.split('\n')
                            .map(s => s.trim())
                            .filter(s => s.length > 0)
                        : [];

                    payload.rule_settings = {
                        enabled: ruleSettings.enabled !== false, // Default true
                        disabled_categories: ruleSettings.disabledCategories || [],
                        blocked_keywords: blockedKeywords,
                    };
                }

                const options = {
                    method: 'POST' as const,
                    url: `${baseUrl}/v1/detect`,
                    body: payload,
                    json: true,
                    headers: {
                        'Authorization': `Bearer ${apiKey}`,
                        'Content-Type': 'application/json',
                    },
                };

                const response = await this.helpers.httpRequest(options);

                returnData.push({
                    json: response,
                    pairedItem: {
                        item: i,
                    },
                });
            } catch (error) {
                // Enhanced error handling with user-friendly messages
                const e = error as {
                    message: string;
                    response?: {
                        status?: number;
                        body?: {
                            detail?: string;
                            error?: string;
                        };
                        data?: {
                            detail?: string;
                            error?: string;
                        };
                    };
                    statusCode?: number;
                };
                let errorMessage = e.message;
                let errorDetails = '';

                // Check if it's an HTTP error
                if (e.response) {
                    const statusCode = e.response.status || e.statusCode;
                    const responseBody = e.response.body || e.response.data;

                    switch (statusCode) {
                        case 401:
                            errorMessage = 'Authentication failed';
                            errorDetails = 'Invalid API key. Please check your Antijection API credentials.';
                            break;
                        case 403:
                            errorMessage = 'Access forbidden';
                            errorDetails = 'Your API key does not have permission to access this resource.';
                            break;
                        case 429:
                            errorMessage = 'Rate limit exceeded';
                            errorDetails = 'You have exceeded your API rate limit or credit quota. Please upgrade your plan or wait before retrying.';
                            break;
                        case 400:
                            errorMessage = 'Invalid request';
                            errorDetails = responseBody?.detail || responseBody?.error || 'The request was malformed. Check your input parameters.';
                            break;
                        case 500:
                        case 502:
                        case 503:
                            errorMessage = 'Antijection API error';
                            errorDetails = 'The Antijection service is temporarily unavailable. Please try again later.';
                            break;
                        default:
                            errorMessage = `HTTP ${statusCode} error`;
                            errorDetails = responseBody?.detail || responseBody?.error || e.message;
                    }
                }

                if (this.continueOnFail()) {
                    returnData.push({
                        json: {
                            error: errorMessage,
                            details: errorDetails,
                            statusCode: e.response?.status || e.statusCode,
                        },
                        pairedItem: {
                            item: i,
                        },
                    });
                    continue;
                }

                const fullError = errorDetails ? `${errorMessage}: ${errorDetails}` : errorMessage;
                throw new NodeOperationError(this.getNode(), fullError, {
                    itemIndex: i,
                });
            }
        }

        return [returnData];
    }
}
