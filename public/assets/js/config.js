/**
 * Configuration for BLT-NetGuardian
 */
const CONFIG = {
    // Frontend and API are served from the same Cloudflare Worker
    API_BASE_URL: (typeof window !== "undefined" && window.location)
        ? window.location.origin
        : "",

    // API endpoints
    ENDPOINTS: {
        QUEUE_TASKS: "/api/tasks/queue",
        REGISTER_TARGET: "/api/targets/register",
        INGEST_RESULTS: "/api/results/ingest",
        JOB_STATUS: "/api/jobs/status",
        LIST_TASKS: "/api/tasks/list",
        VULNERABILITIES: "/api/vulnerabilities"
    },

    // Request timeout (ms)
    REQUEST_TIMEOUT: 30000
};

/**
 * Build full API URL
 */
function buildApiUrl(endpoint) {
    return `${CONFIG.API_BASE_URL}${endpoint}`;
}

/**
 * Make API request with timeout + error handling
 */
async function apiRequest(endpoint, options = {}) {
    const url = buildApiUrl(endpoint);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    try {
        const response = await fetch(url, {
            method: options.method || "GET",
            headers: {
                "Content-Type": "application/json",
                ...(options.headers || {})
            },
            body: options.body ? JSON.stringify(options.body) : undefined,
            signal: controller.signal
        });

        clearTimeout(timeout);

        if (!response.ok) {
            let errorData = {};
            try {
                errorData = await response.json();
            } catch {
                errorData = {
                    error: "Request failed",
                    message: `HTTP ${response.status}: ${response.statusText}`
                };
            }

            throw new Error(
                errorData.message || errorData.error || "Request failed"
            );
        }

        return await response.json();
    } catch (error) {
        if (error.name === "AbortError") {
            throw new Error("Request timeout - please try again");
        }
        throw error;
    }
}
// Example usage
await apiRequest(CONFIG.ENDPOINTS.QUEUE_TASKS, {
    method: "POST",
    body: { task: "scan" }
});
