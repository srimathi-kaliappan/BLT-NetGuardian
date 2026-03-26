/**
 * Dashboard JavaScript for BLT-NetGuardian
 */

let currentJobId = null;
let allJobs = [];

document.addEventListener("DOMContentLoaded", () => {
    const urlParams = new URLSearchParams(window.location.search);
    currentJobId = urlParams.get("job_id");

    const jobsSearch = document.getElementById("jobsSearch");
    if (jobsSearch) {
        jobsSearch.addEventListener("input", applyJobFilters);
    }

    const jobsStatusFilter = document.getElementById("jobsStatusFilter");
    if (jobsStatusFilter) {
        jobsStatusFilter.addEventListener("change", applyJobFilters);
    }

    const jobsTableBody = document.getElementById("jobsTableBody");
    if (jobsTableBody) {
        jobsTableBody.addEventListener("click", handleJobsTableClick);
    }

    loadDashboard();
    setInterval(loadDashboard, 10000);
});

async function loadDashboard() {
    loadStatistics();

    if (currentJobId) {
        await loadCurrentJob(currentJobId);
    }

    loadRecentJobs();
}

function loadStatistics() {
    const stats = {
        totalJobs: Number(localStorage.getItem("totalJobs")) || 0,
        activeJobs: Number(localStorage.getItem("activeJobs")) || 0,
        totalVulnerabilities: Number(localStorage.getItem("totalVulnerabilities")) || 0,
        criticalVulns: Number(localStorage.getItem("criticalVulns")) || 0
    };

    //  Prevent null errors
    document.getElementById("totalJobs")?.textContent = stats.totalJobs;
    document.getElementById("activeJobs")?.textContent = stats.activeJobs;
    document.getElementById("totalVulnerabilities")?.textContent = stats.totalVulnerabilities;
    document.getElementById("criticalVulns")?.textContent = stats.criticalVulns;
}

async function loadCurrentJob(jobId) {
    const section = document.getElementById("currentJobSection");
    const statusDiv = document.getElementById("currentJobStatus");

    if (!section || !statusDiv) return; //  safety check

    section.classList.remove("hidden");
    section.style.display = "block";

    statusDiv.innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <p>Loading job status...</p>
        </div>
    `;

    try {
        const data = await apiRequest(
            `${CONFIG.ENDPOINTS.JOB_STATUS}?job_id=${encodeURIComponent(jobId)}`
        );

        const progressPercent = data.progress || 0;
        const statusClass = data.status || "queued";

        statusDiv.innerHTML = `
            <div class="rounded-lg border p-4">
                <div class="flex justify-between">
                    <h4>Job ${escapeHtml(data.job_id || "unknown")}</h4>
                    <span class="status ${escapeHtml(statusClass)}">
                        ${escapeHtml(data.status || "queued")}
                    </span>
                </div>

                <p>
                    Progress: ${data.completed || 0}/${data.total || 0}
                    (${progressPercent}%)
                </p>

                <div class="progress-bar">
                    <div style="width:${progressPercent}%"></div>
                </div>

                <p>
                    Created:
                    ${data.created_at ? new Date(data.created_at).toLocaleString() : "N/A"}
                </p>
            </div>
        `;
    } catch (error) {
        statusDiv.innerHTML = `
            <div class="error">
                Failed to load job: ${escapeHtml(error.message)}
            </div>
        `;
    }
}

function loadRecentJobs() {
    const jobsLoading = document.getElementById("jobsLoading");

    try {
        allJobs = JSON.parse(localStorage.getItem("recentJobs") || "[]");
    } catch {
        allJobs = []; //  prevent crash if JSON corrupted
    }

    if (jobsLoading) jobsLoading.style.display = "none";

    applyJobFilters();
}

function applyJobFilters() {
    const query = document.getElementById("jobsSearch")?.value?.toLowerCase() || "";
    const statusFilter = document.getElementById("jobsStatusFilter")?.value?.toLowerCase() || "";

    const filteredJobs = allJobs.filter(job => {
        const jobId = String(job.job_id || "").toLowerCase();
        const target = String(job.target || "").toLowerCase();
        const status = String(job.status || "").toLowerCase();

        return (
            (!query || jobId.includes(query) || target.includes(query)) &&
            (!statusFilter || status === statusFilter)
        );
    });

    renderJobs(filteredJobs);
}

function renderJobs(jobsData) {
    const jobsTable = document.getElementById("jobsTable");
    const jobsEmpty = document.getElementById("jobsEmpty");
    const tbody = document.getElementById("jobsTableBody");

    if (!jobsTable || !jobsEmpty || !tbody) return; //  safety

    if (!jobsData.length) {
        jobsEmpty.style.display = "block";
        jobsTable.style.display = "none";
        tbody.innerHTML = "";
        return;
    }

    jobsEmpty.style.display = "none";
    jobsTable.style.display = "table";

    tbody.innerHTML = jobsData.map(job => {
        const safeId = escapeHtml(job.job_id || "unknown");

        return `
            <tr>
                <td><code>${safeId}</code></td>
                <td>${escapeHtml(job.target || "N/A")}</td>
                <td>${escapeHtml(job.status || "queued")}</td>
                <td>${job.progress || 0}%</td>
                <td>
                    ${job.created_at ? new Date(job.created_at).toLocaleDateString() : "N/A"}
                </td>
                <td>
                    <button data-job-id="${safeId}">View</button>
                </td>
            </tr>
        `;
    }).join("");
}

function viewJob(jobId) {
    if (!jobId) return;
    window.location.href = `dashboard.html?job_id=${encodeURIComponent(jobId)}`;
}

function refreshDashboard() {
    loadDashboard();
}

function addRecentJob(jobData) {
    let recentJobs = [];

    try {
        recentJobs = JSON.parse(localStorage.getItem("recentJobs") || "[]");
    } catch {
        recentJobs = [];
    }

    recentJobs.unshift(jobData);
    recentJobs = recentJobs.slice(0, 20);

    localStorage.setItem("recentJobs", JSON.stringify(recentJobs));

    const totalJobs = (Number(localStorage.getItem("totalJobs")) || 0) + 1;
    const activeJobs = (Number(localStorage.getItem("activeJobs")) || 0) + 1;

    localStorage.setItem("totalJobs", totalJobs);
    localStorage.setItem("activeJobs", activeJobs);

    loadDashboard();
}

function handleJobsTableClick(event) {
    const button = event.target.closest("button[data-job-id]");
    if (!button) return;

    viewJob(button.getAttribute("data-job-id"));
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// expose globally
window.refreshDashboard = refreshDashboard;
window.viewJob = viewJob;
window.addRecentJob = addRecentJob;
