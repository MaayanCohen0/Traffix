let selectedAgentId = "all";
const charts = {};

const API_BASE_URL = `http://${window.location.hostname}:8000`;

let map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);

const countryCoords = {
    "Israel": [31.0461, 34.8516], "United States": [37.0902, -95.7129],
    "Germany": [51.1657, 10.4515], "Netherlands": [52.1326, 5.2913],
    "United Kingdom": [55.3781, -3.4360], "Unknown": [0, 0]
};

function initCharts() {
    const configs = { countryChart: 'doughnut', softwareChart: 'bar', ipChart: 'pie' };
    for (const [id, type] of Object.entries(configs)) {
        charts[id] = new Chart(document.getElementById(id), {
            type: type,
            data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00d2ff', '#92fe9d', '#ff7eb3', '#ff758c', '#fad0c4'] }] },
            options: { responsive: true, plugins: { legend: { display: type !== 'bar', labels: { color: '#fff' } } } }
        });
    }
    charts.bandwidthChart = new Chart(document.getElementById('bandwidthChart'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'MB Used', data: [], backgroundColor: '#fbbf24' }] },
        options: { indexAxis: 'y', responsive: true, plugins: { legend: { display: false } } }
    });
}

const socket = new WebSocket(`ws://${window.location.hostname}:8000/ws`);

socket.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.security_event) showSecurityAlert(data.security_event, data.destination_ip);
    
    updateLog(data);
    if (data.direction === "out") addPing(data.country);

    if (selectedAgentId === "all" || data.agent_id == selectedAgentId) {
        updateChart(charts.countryChart, data.country);
        updateChart(charts.softwareChart, data.software_name);
        updateChart(charts.ipChart, data.destination_ip);
    }
};

function addPing(country) {
    const coords = countryCoords[country] || [Math.random() * 50, Math.random() * 50];
    const circle = L.circleMarker(coords, { radius: 10, fillColor: "#00d2ff", color: "#fff", weight: 1, fillOpacity: 0.8 }).addTo(map);
    setTimeout(() => map.removeLayer(circle), 1000);
}

function showSecurityAlert(type, target) {
    const box = document.getElementById('security-alerts');
    const el = document.createElement('div');
    el.className = 'security-banner';
    el.innerHTML = `⚠️ <strong>SECURITY ALERT:</strong> ${type} on target ${target}`;
    document.body.prepend(el);
    setTimeout(() => el.remove(), 8000);
}

function updateChart(chart, label) {
    const idx = chart.data.labels.indexOf(label);
    if (idx > -1) { chart.data.datasets[0].data[idx]++; }
    else { chart.data.labels.push(label); chart.data.datasets[0].data.push(1); }
    chart.update();
}

async function updateDashboard() {
    selectedAgentId = document.getElementById('agentSelect').value;
    const timeframe = document.getElementById('timeframeSelect').value;
    Object.values(charts).forEach(c => { c.data.labels = []; c.data.datasets[0].data = []; });

    const res = await fetch(`${API_BASE_URL}/api/stats/${selectedAgentId}?timeframe=${timeframe}`);
    const data = await res.json();
    fill(charts.countryChart, data.countries);
    fill(charts.softwareChart, data.softwares);
    fill(charts.ipChart, data.ips);
    fill(charts.bandwidthChart, data.bandwidth);
}

function fill(chart, items) {
    items.forEach(i => { chart.data.labels.push(i.label); chart.data.datasets[0].data.push(i.value); });
    chart.update();
}

async function loadAgents() {
    const res = await fetch(`${API_BASE_URL}/api/agents`);
    const agents = await res.json();
    const s = document.getElementById('agentSelect');
    agents.forEach(a => {
        const o = document.createElement('option');
        o.value = a.id; o.textContent = `${a.name} (${a.ip})`;
        s.appendChild(o);
    });
}

function updateLog(data) {
    const log = document.getElementById('log-container');
    const d = document.createElement('div');
    d.className = `log-entry ${data.alert ? 'alert-entry' : ''}`;
    d.innerHTML = `<small>${new Date().toLocaleTimeString()}</small> | <b>${data.software_name}</b> -> ${data.destination_ip}`;
    log.prepend(d);
    if (log.childNodes.length > 50) log.removeChild(log.lastChild);
}
async function confirmReset() {
    // Confirmation dialog to prevent accidental resets
    const isSure = confirm("Are you sure? This will delete ALL traffic logs and agent history.");
    
    if (isSure) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/admin/reset-db`, {
                method: 'POST', 
            });

            const result = await response.json();

            if (result.status === "success") {
                alert("Database cleared successfully!");
                location.reload();
            } else {
                alert("Error: " + result.message);
            }
        } catch (error) {
            console.error("Failed to reset DB:", error);
            alert("Could not connect to the server.");
        }
    }
}

initCharts();
loadAgents();
updateDashboard();