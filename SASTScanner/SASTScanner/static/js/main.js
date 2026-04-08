/* SAST Scanner – main.js */

// ─── Auto-dismiss flash messages ──────────────────────────────────────────────
document.querySelectorAll('.flash').forEach(el => {
  setTimeout(() => el.remove(), 6000);
});

// ─── Dropdown close on outside click ─────────────────────────────────────────
document.addEventListener('click', e => {
  if (!e.target.closest('.dropdown')) {
    document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = '');
  }
});

// ─── Sidebar collapse persist ─────────────────────────────────────────────────
(function () {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  if (localStorage.getItem('sidebar-collapsed') === 'true') {
    sidebar.classList.add('collapsed');
  }
  document.querySelector('.menu-toggle')?.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
    localStorage.setItem('sidebar-collapsed', sidebar.classList.contains('collapsed'));
  });
})();

// ─── Table row highlight on click ─────────────────────────────────────────────
document.querySelectorAll('.data-table tbody tr').forEach(row => {
  row.style.cursor = 'pointer';
  row.addEventListener('click', e => {
    if (e.target.tagName === 'A' || e.target.tagName === 'BUTTON' || e.target.closest('a, button')) return;
    document.querySelectorAll('.data-table tbody tr.selected').forEach(r => r.classList.remove('selected'));
    row.classList.add('selected');
  });
});

// ─── Copy to clipboard for code snippets ─────────────────────────────────────
document.querySelectorAll('.code-snippet').forEach(el => {
  el.title = 'Click to copy';
  el.addEventListener('click', () => {
    navigator.clipboard?.writeText(el.textContent).then(() => {
      const orig = el.style.outline;
      el.style.outline = '1px solid #6c63ff';
      setTimeout(() => { el.style.outline = orig; }, 800);
    });
  });
});
