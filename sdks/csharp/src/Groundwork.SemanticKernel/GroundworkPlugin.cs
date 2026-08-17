using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.SemanticKernel;

namespace Groundwork.SemanticKernel;

/// <summary>
/// A Semantic Kernel plugin that forwards a search query to the Groundwork
/// zero‑trust query runtime and returns the candidate chunks as a JSON
/// string.
/// </summary>
public class GroundworkPlugin
{
    private readonly HttpClient _httpClient;
    private readonly string _runtimeEndpoint;

    /// <summary>
    /// Initialises the plugin with an <see cref="HttpClient"/> and the base
    /// URL of the Groundwork query runtime.
    /// </summary>
    /// <param name="httpClient">An <see cref="HttpClient"/> instance configured
    /// with the appropriate authentication (e.g. Entra ID) for the runtime.</param>
    /// <param name="runtimeEndpoint">
    /// The base URL of the Groundwork query runtime (e.g.
    /// ``https://runtime.example.com``).
    /// </param>
    public GroundworkPlugin(HttpClient httpClient, string runtimeEndpoint)
    {
        _httpClient = httpClient;
        _runtimeEndpoint = runtimeEndpoint;
    }

    /// <summary>
    /// Performs a permission‑filtered search against the Groundwork runtime
    /// and returns the resulting chunks as a JSON string.
    /// </summary>
    /// <param name="query">The search query text.</param>
    /// <param name="userId">The identity of the user / agent submitting the query.</param>
    /// <param name="topK">The maximum number of citation chunks to return.</param>
    /// <returns>A JSON string representing the candidate chunks.</returns>
    [KernelFunction]
    public string SearchContext(string query, string userId, int topK)
    {
        var requestBody = new
        {
            user_id = userId,
            question = query,
            top_k = topK
        };

        var json = JsonSerializer.Serialize(requestBody,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });

        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = _httpClient.PostAsync(
            $"{_runtimeEndpoint}/v1/query", content).Result;

        response.EnsureSuccessStatusCode();

        var responseJson = response.Content.ReadAsStringAsync().Result;
        var groundworkResponse = JsonSerializer.Deserialize<GroundworkResponse>(
            responseJson,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });

        // Format candidate chunks as a JSON string
        if (groundworkResponse?.Citations == null ||
            groundworkResponse.Citations.Count == 0)
        {
            return "[]";
        }

        var chunks = groundworkResponse.Citations.Select(c => new ChunkDto
        {
            DocumentId = c.DocumentId,
            ChunkId = c.ChunkId,
            Score = c.Score,
            Text = c.Text
        });

        return JsonSerializer.Serialize(chunks,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
    }

    private class GroundworkResponse
    {
        public List<Citation> Citations { get; set; } = new();
    }

    private class Citation
    {
        /// <summary>
        /// The document identifier.
        /// </summary>
        public string DocumentId { get; set; } = string.Empty;

        /// <summary>
        /// The chunk identifier.
        /// </summary>
        public string ChunkId { get; set; } = string.Empty;

        /// <summary>
        /// The retrieval score from the runtime.
        /// </summary>
        public double Score { get; set; }

        /// <summary>
        /// The chunk text / content.
        /// </summary>
        public string Text { get; set; } = string.Empty;
    }

    private class ChunkDto
    {
        public string DocumentId { get; set; } = string.Empty;
        public string ChunkId { get; set; } = string.Empty;
        public double Score { get; set; }
        public string Text { get; set; } = string.Empty;
    }
}