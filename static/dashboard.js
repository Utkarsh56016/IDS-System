let chart = null;
let protoChart = null;
let ppsChart = null;
let lastAlerts = [];
const MAX_POINTS = 40;
const PPS_MAX_POINTS = 60;
const LOCALHOST_TOGGLE_KEY = "ignore_localhost_flows";

function getIgnoreLocalhostState() {
    const v = localStorage.getItem(LOCALHOST_TOGGLE_KEY);
    if (v === null) {
        return false;
    }
    return v === "true";
}

function setIgnoreLocalhostState(enabled) {
    localStorage.setItem(LOCALHOST_TOGGLE_KEY, enabled ? "true" : "false");
}

function humanTime(ts) {
    return new Date(ts * 1000).toLocaleTimeString();
}

function protoName(proto) {
    if (proto === 6) return "TCP";
    if (proto === 17) return "UDP";
    if (proto === 1) return "ICMP";
    return proto;
}

// Build alert row with severity + metadata
function buildAlertHtml(item) {
    const score = item.score.toFixed(3);
    const t = humanTime(item.time);

    const src = item.src_ip || "-";
    const dst = item.dst_ip || "-";
    const sport = item.sport || "-";
    const dport = item.dport || "-";
    const proto = protoName(item.proto);

    const conn = `${src}:${sport} → ${dst}:${dport} (${proto})`;

    const sev = item.sev || "low";
    const category = item.category || "";
    const categoryLabel = category ? category.replace(/_/g, " ") : "";

    return `
        <div class="alert-row alert-${sev}">
            <div class="alert-left">
                <div class="alert-score">${score}</div>
                <div class="alert-time">${t}</div>
            </div>

            <div class="alert-right">
                <div class="alert-conn">${conn}</div>
                <div class="alert-badge">${sev.toUpperCase()}</div>
                ${categoryLabel ? `<div class="alert-meta">${categoryLabel}</div>` : ""}
            </div>
        </div>
    `;
}

// Fetch anomaly alerts
async function fetchAlerts() {
    try {
        const res = await fetch("/get_alerts");
        const data = await res.json();

        const ignoreLocalhost = getIgnoreLocalhostState();
        const filtered = ignoreLocalhost
            ? data.filter(item => !(item.src_ip === "127.0.0.1" && item.dst_ip === "127.0.0.1"))
            : data;

        lastAlerts = filtered;

        document.getElementById("sys-status").innerText = "Running";
        document.getElementById("last-update").innerText = new Date().toLocaleTimeString();
        document.getElementById("alert-count").innerText = filtered.length;

        const alertsEl = document.getElementById("alerts");
        const distanceFromBottom = alertsEl.scrollHeight - alertsEl.clientHeight - alertsEl.scrollTop;
        const wasAtBottom = distanceFromBottom <= 5;

        if (filtered.length === 0) {
            alertsEl.innerHTML = "<div style='padding:10px;color:#666'>No recent anomalies</div>";
        } else {
            // Keep alerts in chronological order and show newest at the bottom
            alertsEl.innerHTML = filtered.map(buildAlertHtml).join("");
            // Only auto-scroll if user was already at the bottom before update
            if (wasAtBottom) {
                alertsEl.scrollTop = alertsEl.scrollHeight;
            }
        }

        // Graph update
        const recent = filtered.slice(-MAX_POINTS);
        const scores = recent.map(a => a.score);
        const times = recent.map(a => humanTime(a.time));
        updateChart(times, scores);

        // Compute anomalies/min on the frontend so it respects Ignore Localhost
        const nowSec = Date.now() / 1000;
        const recentSevere = filtered.filter(a =>
            (a.sev === "medium" || a.sev === "high") &&
            (nowSec - a.time) <= 60
        );
        document.getElementById("anoms-min").innerText = recentSevere.length;

    } catch (err) {
        console.error("fetchAlerts error:", err);
        document.getElementById("sys-status").innerText = "Error";
    }
}

// Fetch packets/sec and anomalies/min
async function fetchStats() {
    try {
        const res = await fetch("/get_stats");
        const data = await res.json();

        document.getElementById("packets-sec").innerText = data.pps;
        const rawAnomsEl = document.getElementById("anoms-min-raw");
        if (rawAnomsEl) {
            rawAnomsEl.innerText = data.anoms_min;
        }

        updatePpsSeries(data.pps);

    } catch (err) {
        console.error("stats error", err);
    }
}

let ppsLabels = [];
let ppsValues = [];
let ppsSmoothed = null;

function updatePpsSeries(pps) {
    const alpha = 0.3; // smoothing factor (0..1), lower = smoother
    if (ppsSmoothed === null) {
        ppsSmoothed = pps;
    } else {
        ppsSmoothed = alpha * pps + (1 - alpha) * ppsSmoothed;
    }

    const nowLabel = new Date().toLocaleTimeString();
    ppsLabels.push(nowLabel);
    ppsValues.push(ppsSmoothed);
    if (ppsLabels.length > PPS_MAX_POINTS) {
        ppsLabels.shift();
        ppsValues.shift();
    }
    updatePpsChart(ppsLabels, ppsValues);
}

function updatePpsChart(labels, values) {
    if (!ppsChart) {
        const canvas = document.getElementById("ppsChart");
        if (!canvas) {
            return;
        }
        const ctx = canvas.getContext("2d");
        ppsChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    borderWidth: 1,
                    tension: 0.25,
                    pointRadius: 0,
                    fill: true,
                    backgroundColor: "rgba(0,0,0,0.03)",
                    borderColor: "#000000"
                }]
            },
            options: {
                animation: false,
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: false },
                    y: { display: false }
                }
            }
        });
        return;
    }

    ppsChart.data.labels = labels;
    ppsChart.data.datasets[0].data = values;
    ppsChart.update("none");
}

async function fetchProtoCounts() {
    try {
        const res = await fetch("/get_protocol_counts");
        const data = await res.json();

        const entries = Object.entries(data || {});
        if (entries.length === 0) {
            return;
        }

        const labels = entries.map(([proto]) => protoName(parseInt(proto, 10)));
        const rawCounts = entries.map(([, count]) => count);
        // Use a square-root scale so very noisy protocols (like ICMP) don't visually drown out others
        const counts = rawCounts.map(c => Math.sqrt(c));
        if (!protoChart) {
            const ctx = document.getElementById("protoChart").getContext("2d");
            protoChart = new Chart(ctx, {
                type: "pie",
                data: {
                    labels: labels,
                    datasets: [{
                        data: counts,
                        backgroundColor: [
                            "#000000",
                            "#555555",
                            "#999999",
                            "#DDDDDD"
                        ],
                        borderWidth: 0,
                        hoverOffset: 2
                    }]
                },
                options: {
                    animation: false,
                    layout: {
                        padding: { top: 8, right: 8, bottom: 8, left: 8 }
                    },
                    plugins: {
                        legend: {
                            display: true,
                            position: "right",
                            align: "right",
                            labels: {
                                boxWidth: 8,
                                boxHeight: 8,
                                usePointStyle: true,
                                padding: 4,
                                font: { size: 9 }
                            }
                        }
                    }
                }
            });
        } else {
            protoChart.data.labels = labels;
            protoChart.data.datasets[0].data = counts;
            protoChart.update("none");
        }

    } catch (err) {
        console.error("proto counts error", err);
    }
}

async function fetchTopTalkers() {
    try {
        const res = await fetch("/get_top_talkers");
        const data = await res.json();

        const tbody = document.getElementById("top-talkers-body");
        if (!tbody) {
            return;
        }

        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="font-size:11px;color:#666">No data yet</td></tr>';
            return;
        }

        const rows = data.map((row, idx) => {
            const rank = idx + 1;
            const ip = row.ip;
            const packets = row.packets;
            const bytes = row.bytes;
            const flows = row.flows;
            return `<tr><td>${rank}</td><td>${ip}</td><td>${packets}</td><td>${bytes}</td><td>${flows}</td></tr>`;
        });
        tbody.innerHTML = rows.join("");

    } catch (err) {
        console.error("top talkers error", err);
    }
}

// Chart update function
function updateChart(labels, points) {
    if (!chart) {
        const ctx = document.getElementById("scoreChart").getContext("2d");
        chart = new Chart(ctx, {
            type: "line",
            data: {
                labels: labels,
                datasets: [{
                    label: "Anomaly score",
                    data: points,
                    borderWidth: 1,
                    tension: 0.25,
                    pointRadius: 2,
                    fill: true,
                    backgroundColor: "rgba(0,0,0,0.05)",
                    borderColor: "#000000"
                }]
            },
            options: {
                animation: false,
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: true },
                    y: { display: true }
                }
            }
        });
        return;
    }

    chart.data.labels = labels;
    chart.data.datasets[0].data = points;
    chart.update("none");
}

function csvEscape(value) {
    const s = String(value == null ? "" : value);
    return '"' + s.replace(/"/g, '""') + '"';
}

function buildCsv(alerts) {
    const header = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "sport",
        "dport",
        "protocol",
        "severity",
        "score",
        "category"
    ].join(",");

    const lines = alerts.map(a => {
        const ts = new Date(a.time * 1000).toISOString();
        const src = a.src_ip || "";
        const dst = a.dst_ip || "";
        const sport = a.sport || "";
        const dport = a.dport || "";
        const proto = protoName(a.proto);
        const sev = a.sev || "";
        const score = typeof a.score === "number" ? a.score.toFixed(3) : a.score;
        const category = a.category || "";

        return [ts, src, dst, sport, dport, proto, sev, score, category].map(csvEscape).join(",");
    });

    return header + "\n" + lines.join("\n");
}

function exportAlertsToCsv() {
    if (!lastAlerts || lastAlerts.length === 0) {
        const headerOnly = "timestamp,src_ip,dst_ip,sport,dport,protocol,severity,score,category\n";
        const blobEmpty = new Blob([headerOnly], { type: "text/csv;charset=utf-8;" });
        const urlEmpty = URL.createObjectURL(blobEmpty);
        const linkEmpty = document.createElement("a");
        linkEmpty.href = urlEmpty;
        linkEmpty.download = "alerts_export_empty.csv";
        document.body.appendChild(linkEmpty);
        linkEmpty.click();
        document.body.removeChild(linkEmpty);
        URL.revokeObjectURL(urlEmpty);
        return;
    }

    const csv = buildCsv(lastAlerts);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const tsName = new Date().toISOString().replace(/[:.]/g, "-");
    link.href = url;
    link.download = `alerts_export_${tsName}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function initIgnoreLocalhostToggle() {
    const checkbox = document.getElementById("ignore-localhost-toggle");
    if (!checkbox) {
        return;
    }
    checkbox.checked = getIgnoreLocalhostState();
    checkbox.addEventListener("change", function () {
        setIgnoreLocalhostState(checkbox.checked);
    });
}

function initExportCsvButton() {
    const btn = document.getElementById("export-csv-btn");
    if (!btn) {
        return;
    }
    btn.addEventListener("click", exportAlertsToCsv);
}

// Start polling
initIgnoreLocalhostToggle();
initExportCsvButton();
fetchAlerts();
setInterval(fetchAlerts, 2000);

fetchStats();
setInterval(fetchStats, 1000);

fetchTopTalkers();
setInterval(fetchTopTalkers, 2000);

fetchProtoCounts();
setInterval(fetchProtoCounts, 2000);
