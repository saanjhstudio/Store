(() => {
  let ghost = false, queue = [];
  const sid = (() => {
    try { let s = sessionStorage.getItem('sid'); if (!s) sessionStorage.setItem('sid', s = crypto.randomUUID()); return s; }
    catch { return crypto.randomUUID(); }
  })();

  // Console: `ghostmode = true`. Lives only in memory, so a refresh turns tracking back on.
  Object.defineProperty(window, 'ghostmode', {
    get: () => ghost,
    set: v => {
      ghost = !!v;
      if (ghost) queue = [];
      console.log(ghost ? '👻 Ghost mode ON. Nothing is tracked until you refresh.' : 'Ghost mode OFF. Tracking resumed.');
    }
  });

  const extRef = () => { try { const h = new URL(document.referrer).hostname; return h === location.hostname ? '' : h; } catch { return ''; } };

  // track('page_view') | track('product_view', id) | track('order_click', id) | track('social_click')
  window.track = (type, productId = null) => {
    if (ghost) return;
    queue.push({ type, product_id: productId, path: location.pathname, ref: type === 'page_view' ? extRef() : '', sid });
    if (queue.length >= 10) flush();
  };

  function flush() {
    if (ghost || !queue.length) return;
    const body = JSON.stringify({ events: queue.splice(0, 20) });
    const sent = navigator.sendBeacon && navigator.sendBeacon('/api/track', new Blob([body], { type: 'application/json' }));
    if (!sent) fetch('/api/track', { method: 'POST', body, headers: { 'Content-Type': 'application/json' }, keepalive: true }).catch(() => {});
  }
  setInterval(flush, 5000);
  addEventListener('visibilitychange', () => document.visibilityState === 'hidden' && flush());
  addEventListener('pagehide', flush);
})();
