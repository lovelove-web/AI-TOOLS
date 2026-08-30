(() => {
  const nav = document.getElementById("siteNav");
  const year = document.getElementById("year");
  const form = document.getElementById("contactForm");
  const status = document.getElementById("formStatus");
  const navLinks = document.querySelectorAll("#primaryNav .nav-link[data-nav]");
  const collapseEl = document.getElementById("primaryNav");
  const currentPage = document.body.dataset.page || "";

  if (year) {
    year.textContent = String(new Date().getFullYear());
  }

  navLinks.forEach((link) => {
    link.classList.toggle("active", link.dataset.nav === currentPage);
  });

  const onScroll = () => {
    if (!nav) return;
    nav.classList.toggle("scrolled", window.scrollY > 24);
  };

  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  document.querySelectorAll("#primaryNav .nav-link, #primaryNav .btn").forEach((link) => {
    link.addEventListener("click", () => {
      if (window.bootstrap && collapseEl && collapseEl.classList.contains("show")) {
        const instance = window.bootstrap.Collapse.getInstance(collapseEl)
          || new window.bootstrap.Collapse(collapseEl, { toggle: false });
        instance.hide();
      }
    });
  });

  const revealTargets = document.querySelectorAll(
    ".glass-card, .service-card, .product-card, .story-card, .cta-panel, .contact-form, .section-head, .preview-card, .detail-aside, .detail-content"
  );
  revealTargets.forEach((el) => el.classList.add("reveal"));

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.08, rootMargin: "0px 0px -40px 0px" }
    );
    revealTargets.forEach((el) => observer.observe(el));
    // Fail-safe so content never stays hidden if the observer misses
    window.setTimeout(() => {
      revealTargets.forEach((el) => el.classList.add("visible"));
    }, 1200);
  } else {
    revealTargets.forEach((el) => el.classList.add("visible"));
  }

  const isEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

  form?.addEventListener("submit", (event) => {
    event.preventDefault();
    status.className = "form-status";
    status.textContent = "";

    const name = form.name.value.trim();
    const email = form.email.value.trim();
    const message = form.message.value.trim();

    if (!name || !email || !message) {
      status.classList.add("err");
      status.textContent = "Please fill in name, work email, and a short message.";
      return;
    }

    if (!isEmail(email)) {
      status.classList.add("err");
      status.textContent = "Please enter a valid work email address.";
      return;
    }

    status.classList.add("ok");
    status.textContent = "Thanks — we will reply within one business day.";
    form.reset();
  });
})();
