/**
 * Flowise custom component: Groundwork Security Block
 *
 * Executes a permission-filtered query against the Groundwork runtime and
 * returns an array of Document objects that can be consumed by downstream
 * LLM nodes in a Flowise workflow.
 *
 * Category: "Security & Governance"
 *
 * Inputs
 * ------
 * - groundworkEndpoint  (string) – Runtime base URL, e.g. https://runtime.example.com
 * - apiKey            (string)   – Groundwork API key (or Entra ID token)
 * - userId            (string)   – Identity of the requesting user/agent
 * - query             (string)   – Natural‑language search query
 *
 * Outputs
 * -------
 * - documents (Document[]) – List of Groundwork‑filtered documents,
 *   each with id, text and metadata (score, digest, doc_id, …).
 */
const GroundworkSecurityBlock = {
  id: "groundwork-security",
  name: "Groundwork Security Block",
  description:
    "Runs a permission‑filtered query against the Groundwork runtime and returns Document[].",
  category: "Security & Governance",
  inputs: [
    {
      name: "groundworkEndpoint",
      type: "string",
      required: true,
      placeholder: "https://runtime.example.com",
    },
    {
      name: "apiKey",
      type: "string",
      required: true,
      placeholder: "your-api-key-or-token",
    },
    {
      name: "userId",
      type: "string",
      required: true,
      placeholder: "alice",
    },
    {
      name: "query",
      type: "string",
      required: true,
      placeholder: "What is the policy?",
    },
  ],
  outputs: [
    {
      name: "documents",
      type: "Document[]",
      description:
        "List of Groundwork‑filtered documents returned from the runtime.",
    },
  ],
  execute: async (inputData) => {
    // inputData is keyed by the input names defined above
    const {
      groundworkEndpoint,
      apiKey,
      userId,
      query,
    } = inputData;

    // -------------------------------------------------------------------------
    // In a real deployment you would instantiate the Groundwork client here
    // (using the endpoint + apiKey) and call client.query(userId, query, …).
    // For demonstration purposes we return a static set of documents.
    // -------------------------------------------------------------------------

    const mockDocuments = [
      {
        id: "doc-1",
        text: "Policy document excerpt – data retention period is 30 days.",
        metadata: {
          score: 0.95,
          digest: "a1b2c3d4e5f6...",
          doc_id: "policy‑001",
        },
      },
      {
        id: "doc-2",
        text: "Access‑control list – alice may read /billing.",
        metadata: {
          score: 0.87,
          digest: "f6e5d4c3b2a1...",
          doc_id: "acl‑002",
        },
      },
    ];

    // Flowise expects the execute method to return an object whose keys
    // match the output names defined above.
    return {
      documents: mockDocuments,
    };
  },
};

// Export so Flowise can discover the component (CommonJS for Node‑based Flowise)
module.exports = GroundworkSecurityBlock;