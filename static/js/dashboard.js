/* Dashboard Chart.js initialization. Reads data injected via data-* attributes
   from dashboard/home.html to avoid inline JSON parsing issues. */
document.addEventListener("DOMContentLoaded", function () {
  const el = document.getElementById("dashboard-charts");
  if (!el) return;

  const severityLabels = JSON.parse(el.dataset.severityLabels);
  const severityValues = JSON.parse(el.dataset.severityValues);
  const providerLabels = JSON.parse(el.dataset.providerLabels);
  const providerValues = JSON.parse(el.dataset.providerValues);
  const statusLabels = JSON.parse(el.dataset.statusLabels);
  const statusValues = JSON.parse(el.dataset.statusValues);

  const gridColor = "rgba(150,165,180,0.15)";
  const fontColor = getComputedStyle(document.documentElement).getPropertyValue("--text").trim() || "#333";

  new Chart(document.getElementById("severityChart"), {
    type: "doughnut",
    data: {
      labels: severityLabels,
      datasets: [{
        data: severityValues,
        backgroundColor: ["#d7263d", "#f4743b", "#f2b134", "#4f9df7"],
        borderWidth: 0,
      }],
    },
    options: {
      plugins: { legend: { position: "bottom", labels: { color: fontColor } } },
    },
  });

  new Chart(document.getElementById("providerChart"), {
    type: "bar",
    data: {
      labels: providerLabels,
      datasets: [{
        label: "Cloud Assets",
        data: providerValues,
        backgroundColor: ["#ff9900", "#0078d4", "#4285f4"],
        borderRadius: 6,
      }],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: fontColor }, grid: { color: gridColor } },
        y: { beginAtZero: true, ticks: { color: fontColor }, grid: { color: gridColor } },
      },
    },
  });

  new Chart(document.getElementById("statusChart"), {
    type: "bar",
    data: {
      labels: statusLabels,
      datasets: [{
        label: "Compliance Records",
        data: statusValues,
        backgroundColor: "#17c3b2",
        borderRadius: 6,
      }],
    },
    options: {
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, ticks: { color: fontColor }, grid: { color: gridColor } },
        y: { ticks: { color: fontColor }, grid: { color: gridColor } },
      },
    },
  });
});
