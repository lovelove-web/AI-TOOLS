/* =====================================================================
   PULSE — BMI Calculator
   ---------------------------------------------------------------------
   Sections:
     1. Theme (dark mode) handling
     2. Unit switch (metric / imperial)
     3. BMI math + gauge angle mapping
     4. Recommendations content
     5. Form submit -> calculate -> render result
     6. History (localStorage) CRUD + rendering
   ===================================================================== */

(() => {
  'use strict';

  /* ---------------------------------------------------------------
     1. THEME
     --------------------------------------------------------------- */
  const root = document.documentElement;
  const themeToggle = document.getElementById('themeToggle');
  const themeLabel = document.getElementById('themeLabel');
  const THEME_KEY = 'pulse-theme';

  function applyTheme(theme) {
    const isDark = theme === 'dark';
    root.classList.toggle('dark', isDark);
    themeToggle.setAttribute('aria-checked', String(isDark));
    themeLabel.textContent = isDark ? 'Dark' : 'Light';
  }

  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved) {
      applyTheme(saved);
    } else {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      applyTheme(prefersDark ? 'dark' : 'light');
    }
  }

  themeToggle.addEventListener('click', () => {
    const next = root.classList.contains('dark') ? 'light' : 'dark';
    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
  });

  initTheme();

  /* ---------------------------------------------------------------
     2. UNIT SWITCH
     --------------------------------------------------------------- */
  let currentUnit = 'metric';
  const unitButtons = document.querySelectorAll('.unit-btn');
  const fieldGroups = document.querySelectorAll('.field-group');

  unitButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      currentUnit = btn.dataset.unit;
      unitButtons.forEach((b) => {
        const active = b === btn;
        b.classList.toggle('is-active', active);
        b.setAttribute('aria-selected', String(active));
      });
      fieldGroups.forEach((g) => {
        g.classList.toggle('is-hidden', g.dataset.group !== currentUnit);
      });
      formError.hidden = true;
    });
  });

  /* ---------------------------------------------------------------
     3. BMI MATH
     --------------------------------------------------------------- */

  // Category boundaries used both for classification and for mapping
  // a BMI value onto the 0-360deg gauge (must mirror the conic-gradient
  // stops defined in style.css so the pointer lands in the right zone).
  const ZONES = [
    { key: 'under',  label: 'Underweight', min: 0,    max: 18.5, angleStart: 0,     angleEnd: 78 },
    { key: 'normal', label: 'Healthy weight', min: 18.5, max: 24.9, angleStart: 78,    angleEnd: 154.8 },
    { key: 'over',   label: 'Overweight',  min: 24.9, max: 29.9, angleStart: 154.8, angleEnd: 213.6 },
    { key: 'obese',  label: 'Obese',       min: 29.9, max: 999,  angleStart: 213.6, angleEnd: 360 }
  ];
  const GAUGE_MIN_BMI = 12;
  const GAUGE_MAX_BMI = 42;

  function calculateBmi(heightM, weightKg) {
    return weightKg / (heightM * heightM);
  }

  function classify(bmi) {
    return ZONES.find((z) => bmi < z.max) || ZONES[ZONES.length - 1];
  }

  // Maps a BMI value to a 0-360deg rotation for the gauge pointer.
  // Values are clamped into each zone's angle band, and interpolated
  // within that band the same way the underlying color segments are drawn.
  function bmiToAngle(bmi) {
    const clamped = Math.min(Math.max(bmi, GAUGE_MIN_BMI), GAUGE_MAX_BMI);
    const zone = classify(clamped);
    const zoneMin = zone.key === 'under' ? GAUGE_MIN_BMI : zone.min;
    const zoneMax = zone.key === 'obese' ? GAUGE_MAX_BMI : zone.max;
    const t = (clamped - zoneMin) / (zoneMax - zoneMin);
    return zone.angleStart + t * (zone.angleEnd - zone.angleStart);
  }

  /* ---------------------------------------------------------------
     4. RECOMMENDATIONS
     --------------------------------------------------------------- */
  const RECOMMENDATIONS = {
    under: {
      intro: "Your BMI falls in the underweight range. A bit more fuel and strength work can help you build a stronger baseline.",
      tips: [
        'Add nutrient-dense foods like nuts, whole grains, and healthy fats to your meals.',
        'Include light strength training to build muscle alongside weight gain.',
        'Check in with a doctor or dietitian if weight gain is difficult or unintentional.'
      ]
    },
    normal: {
      intro: "Your BMI is in the healthy range. The goal now is maintaining the habits that got you here.",
      tips: [
        'Keep up a mix of regular movement — aim for both cardio and strength work.',
        'Prioritize sleep and hydration; they affect weight and energy as much as diet.',
        'Recheck your BMI periodically rather than daily — small day-to-day shifts are normal.'
      ]
    },
    over: {
      intro: "Your BMI falls in the overweight range. Small, sustainable changes tend to work better than drastic ones.",
      tips: [
        'Build in regular movement you actually enjoy — consistency beats intensity.',
        'Focus on whole foods and portion awareness rather than strict cutting.',
        'A conversation with a healthcare provider can help set a realistic, personal target.'
      ]
    },
    obese: {
      intro: "Your BMI falls in the obese range. This is a good moment to loop in a healthcare professional for a plan built around you.",
      tips: [
        'Talk to a doctor about a plan that fits your health history and goals.',
        'Start with small, repeatable habits — a daily walk, more vegetables, better sleep.',
        'Track progress with more than the scale — energy, strength, and sleep all matter.'
      ]
    }
  };

  const recoIntro = document.getElementById('recoIntro');
  const recoList = document.getElementById('recoList');

  function renderRecommendations(zoneKey) {
    const data = RECOMMENDATIONS[zoneKey];
    recoIntro.textContent = data.intro;
    recoList.innerHTML = '';
    data.tips.forEach((tip) => {
      const li = document.createElement('li');
      li.innerHTML = `<span class="dot" aria-hidden="true"></span><span>${tip}</span>`;
      recoList.appendChild(li);
    });
  }

  /* ---------------------------------------------------------------
     5. FORM SUBMIT -> CALCULATE -> RENDER
     --------------------------------------------------------------- */
  const form = document.getElementById('bmiForm');
  const formError = document.getElementById('formError');
  const gaugeValue = document.getElementById('gaugeValue');
  const gaugeCategory = document.getElementById('gaugeCategory');
  const gaugePointer = document.getElementById('gaugePointer');

  function readInputs() {
    if (currentUnit === 'metric') {
      const cm = parseFloat(document.getElementById('heightCm').value);
      const kg = parseFloat(document.getElementById('weightKg').value);
      if (!cm || !kg || cm <= 0 || kg <= 0) return null;
      return {
        heightM: cm / 100,
        weightKg: kg,
        heightLabel: `${cm} cm`,
        weightLabel: `${kg} kg`
      };
    }
    const ft = parseFloat(document.getElementById('heightFt').value) || 0;
    const inch = parseFloat(document.getElementById('heightIn').value) || 0;
    const lb = parseFloat(document.getElementById('weightLb').value);
    const totalInches = ft * 12 + inch;
    if (!totalInches || !lb || totalInches <= 0 || lb <= 0) return null;
    return {
      heightM: totalInches * 0.0254,
      weightKg: lb * 0.45359237,
      heightLabel: `${ft}'${inch}"`,
      weightLabel: `${lb} lb`
    };
  }

  // Animates the displayed BMI number counting up from 0 to the target value
  function animateNumber(target) {
    const duration = 700;
    const start = performance.now();
    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      const current = target * eased;
      gaugeValue.textContent = current.toFixed(1);
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function renderResult(bmi, zone) {
    animateNumber(bmi);
    gaugeCategory.textContent = zone.label;
    gaugePointer.style.transform = `rotate(${bmiToAngle(bmi)}deg)`;
    renderRecommendations(zone.key);
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const inputs = readInputs();
    if (!inputs) {
      formError.textContent = 'Please fill in valid height and weight values.';
      formError.hidden = false;
      return;
    }
    formError.hidden = true;

    const bmi = calculateBmi(inputs.heightM, inputs.weightKg);
    const zone = classify(bmi);
    renderResult(bmi, zone);
    saveHistoryEntry(bmi, zone, inputs);
  });

  /* ---------------------------------------------------------------
     6. HISTORY
     --------------------------------------------------------------- */
  const HISTORY_KEY = 'pulse-bmi-history';
  const MAX_HISTORY = 12;

  const historyList = document.getElementById('historyList');
  const historyEmpty = document.getElementById('historyEmpty');
  const clearHistoryBtn = document.getElementById('clearHistory');

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch {
      return [];
    }
  }

  function saveHistoryEntry(bmi, zone, inputs) {
    const history = getHistory();
    history.unshift({
      id: Date.now(),
      date: new Date().toISOString(),
      bmi: Number(bmi.toFixed(1)),
      zoneKey: zone.key,
      zoneLabel: zone.label,
      heightLabel: inputs.heightLabel,
      weightLabel: inputs.weightLabel
    });
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
    renderHistory();
  }

  function deleteHistoryEntry(id) {
    const history = getHistory().filter((entry) => entry.id !== id);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    renderHistory();
  }

  function formatDate(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) +
      ' · ' + d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  }

  function renderHistory() {
    const history = getHistory();
    historyList.innerHTML = '';
    historyEmpty.hidden = history.length > 0;

    history.forEach((entry) => {
      const li = document.createElement('li');
      li.className = 'history-item';
      li.innerHTML = `
        <span class="history-dot" style="background:var(--zone-${entry.zoneKey})"></span>
        <span class="history-meta">
          <span class="h-detail">${entry.zoneLabel} · ${entry.heightLabel}, ${entry.weightLabel}</span>
          <span class="h-date">${formatDate(entry.date)}</span>
        </span>
        <span class="history-value">${entry.bmi}</span>
        <button type="button" class="history-delete" aria-label="Delete this entry">&times;</button>
      `;
      li.querySelector('.history-delete').addEventListener('click', () => deleteHistoryEntry(entry.id));
      historyList.appendChild(li);
    });
  }

  clearHistoryBtn.addEventListener('click', () => {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  });

  // Initial render on page load
  renderHistory();
})();
