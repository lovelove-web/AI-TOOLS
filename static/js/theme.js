(function () {
  const root = document.documentElement;
  const STORAGE_KEY = "csct-theme";
  const saved = localStorage.getItem(STORAGE_KEY) || "dark";
  root.setAttribute("data-theme", saved);

  document.addEventListener("DOMContentLoaded", function () {
    const toggleBtn = document.getElementById("themeToggle");
    const icon = toggleBtn ? toggleBtn.querySelector("i") : null;
    const setIcon = (theme) => {
      if (!icon) return;
      icon.className = theme === "dark" ? "fa-solid fa-sun" : "fa-solid fa-moon";
    };
    setIcon(saved);

    if (toggleBtn) {
      toggleBtn.addEventListener("click", function () {
        const current = root.getAttribute("data-theme");
        const next = current === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        localStorage.setItem(STORAGE_KEY, next);
        setIcon(next);
      });
    }

    const sidebarToggle = document.getElementById("sidebarToggle");
    const sidebar = document.getElementById("sidebar");
    if (sidebarToggle && sidebar) {
      sidebarToggle.addEventListener("click", () => sidebar.classList.toggle("show"));
    }
  });
})();
