/**
 * Vulnerabilities page JavaScript for BLT-NetGuardian
 */

let allVulnerabilities = [];
let displayedVulnerabilities = [];

document.addEventListener("DOMContentLoaded", () => {
    const searchInput = document.getElementById("vulnSearch");
    if (searchInput) {
        searchInput.addEventListener("input", applyFilters);
    }

    const severityFilter = document.getElementById("severityFilter");
    if (severityFilter) {
        severityFilter.addEventListener("change", applyFilters);
    }

    const tableBody = document.getElementById("vulnsTableBody");
    if (tableBody) {
        tableBody.addEventListener("click", handleVulnerabilityRowClick);
    }

    loadVulnerabilities();
});

async function loadVulnerabilities() {
    const vulnsLoading = document.getElementById("vulnsLoading");
    const vulnsTable = document.getElementById("vulnsTable");
    const vulnsEmpty = document.getElementById("vulnsEmpty");

    if (!vulnsLoading || !vulnsTable || !vulnsEmpty) return; //  safety

    vulnsLoading.style.display = "block";
    vulnsTable.style.display = "none";
    vulnsEmpty.style.display = "none";

    try {
        const data = await apiRequest(CONFIG.ENDPOINTS.VULNERABILITIES);

        allVulnerabilities = data?.vulnerabilities || [];

        vulnsLoading.style.display = "none";

        if (!allVulnerabilities.length) {
            vulnsEmpty.textContent = "No vulnerabilities found. Great job.";
            vulnsEmpty.style.display = "block";

            updateSummary({ critical: 0, high: 0, medium: 0, low: 0 });
            displayedVulnerabilities = [];
            return;
        }

        applyFilters();

    } catch (error) {
        console.warn("Using demo data:", error.message);

        vulnsLoading.style.display = "none";

        loadDemoData();
        applyFilters();
    }
}

function loadDemoData() {
    allVulnerabilities = [
        {
            severity: "critical",
            title: "SQL Injection in Login Form",
            type: "sql_injection",
            affected_component: "/login.php",
            cve_id: "CVE-2024-12345",
            cvss_score: 9.8,
            discovered_at: new Date().toISOString()
        },
        {
            severity: "high",
            title: "Cross-Site Scripting (XSS)",
            type: "xss",
            affected_component: "/search",
            cvss_score: 7.5,
            discovered_at: new Date().toISOString()
        }
    ];
}

function displayVulnerabilities(vulnerabilities) {
    const vulnsTable = document.getElementById("vulnsTable");
    const vulnsEmpty = document.getElementById("vulnsEmpty");
    const tbody = document.getElementById("vulnsTableBody");

    if (!vulnsTable || !vulnsEmpty || !tbody) return; //  safety

    displayedVulnerabilities = vulnerabilities;
    updateSummary(getSummary(vulnerabilities));

    if (!vulnerabilities.length) {
        vulnsTable.style.display = "none";
        vulnsEmpty.textContent = "No vulnerabilities match filters.";
        vulnsEmpty.style.display = "block";
        tbody.innerHTML = "";
        return;
    }

    vulnsEmpty.style.display = "none";
    vulnsTable.style.display = "table";

    tbody.innerHTML = vulnerabilities.map((vuln, index) => `
        <tr data-vuln-index="${index}">
            <td>${escapeHtml(vuln.severity || "info")}</td>
            <td><strong>${escapeHtml(vuln.title || "Untitled")}</strong></td>
            <td>${escapeHtml(vuln.type || "N/A")}</td>
            <td>${escapeHtml(vuln.affected_component || "N/A")}</td>
            <td>${escapeHtml(vuln.cve_id || "-")}</td>
            <td>${vuln.cvss_score ? Number(vuln.cvss_score).toFixed(1) : "-"}</td>
            <td>${vuln.discovered_at ? new Date(vuln.discovered_at).toLocaleDateString() : "N/A"}</td>
        </tr>
    `).join("");
}

function updateSummary(summary) {
    document.getElementById("criticalCount")?.textContent = summary.critical;
    document.getElementById("highCount")?.textContent = summary.high;
    document.getElementById("mediumCount")?.textContent = summary.medium;
    document.getElementById("lowCount")?.textContent = summary.low;
}

function getSummary(vulnerabilities) {
    return {
        critical: vulnerabilities.filter(v => v.severity === "critical").length,
        high: vulnerabilities.filter(v => v.severity === "high").length,
        medium: vulnerabilities.filter(v => v.severity === "medium").length,
        low: vulnerabilities.filter(v => v.severity === "low").length
    };
}

function applyFilters() {
    const severity = document.getElementById("severityFilter")?.value?.toLowerCase() || "";
    const query = document.getElementById("vulnSearch")?.value?.toLowerCase() || "";

    const filtered = allVulnerabilities.filter(v => {
        const matchesSeverity = !severity || v.severity === severity;

        const text = `${v.title} ${v.type} ${v.affected_component} ${v.cve_id || ""}`.toLowerCase();
        const matchesQuery = !query || text.includes(query);

        return matchesSeverity && matchesQuery;
    });

    displayVulnerabilities(filtered);
}

function handleVulnerabilityRowClick(event) {
    const row = event.target.closest("tr[data-vuln-index]");
    if (!row) return;

    const index = Number(row.dataset.vulnIndex);
    if (!displayedVulnerabilities[index]) return;

    showVulnerabilityDetails(displayedVulnerabilities[index]);
}

function showVulnerabilityDetails(vuln) {
    alert(`
Severity: ${vuln.severity}
Title: ${vuln.title}
Type: ${vuln.type}
Component: ${vuln.affected_component}
CVSS: ${vuln.cvss_score || "-"}
    `);
}

function refreshVulnerabilities() {
    loadVulnerabilities();
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

window.refreshVulnerabilities = refreshVulnerabilities;
window.filterBySeverity = applyFilters;
window.showVulnerabilityDetails = showVulnerabilityDetails;
