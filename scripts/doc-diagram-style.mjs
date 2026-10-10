// Shared visual language from the illustrated Veyport architecture overview.
// Styling is applied after layout so Mermaid retains control of connections.
export function diagramStyleDefinitions(id) {
  return `<defs>
    <linearGradient id="${id}-card" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#08254e"/>
      <stop offset="1" stop-color="#185aa4"/>
    </linearGradient>
    <filter id="${id}-shadow" x="-10%" y="-20%" width="120%" height="150%">
      <feDropShadow dx="0" dy="3" stdDeviation="3" flood-color="#061c3c" flood-opacity="0.16"/>
    </filter>
  </defs>`;
}

const icons = {
  terminal: '<rect x="2" y="3" width="20" height="18" rx="3"/><path d="m6 8 4 4-4 4m7 0h5"/>',
  browser: '<rect x="2" y="3" width="20" height="18" rx="3"/><path d="M2 8h20m-15-3h1m3 0h1"/>',
  hub: '<path d="m12 1 10 6v10l-10 6-10-6V7Zm0 5v12m-5-7 5-5 5 5"/>',
  server: '<rect x="3" y="2" width="18" height="20" rx="3"/><path d="M7 7h3m4 0h3M7 12h3m4 0h3M7 17h3m4 0h3"/>',
  security: '<path d="m12 1 9 4v7c0 5-5 9-9 11-4-2-9-6-9-11V5Z"/><rect x="8" y="10" width="8" height="7" rx="1"/><path d="M9 10V8a3 3 0 0 1 6 0v2"/>',
  database: '<ellipse cx="12" cy="5" rx="9" ry="4"/><path d="M3 5v14c0 5 18 5 18 0V5M3 12c0 5 18 5 18 0"/>',
};

function iconFor(label) {
  if (/ssh client|vey cli/i.test(label)) return icons.terminal;
  if (/browser|client/i.test(label)) return icons.browser;
  if (/sqlite|database|datastore|audit log/i.test(label)) return icons.database;
  if (/proxy|certificate|cert |\bca\b|authorization|totp/i.test(label)) return icons.security;
  if (/\bhub\b/i.test(label)) return icons.hub;
  if (/ssh|cli|shell|terminal/i.test(label)) return icons.terminal;
  if (/agent|server|container|instance/i.test(label)) return icons.server;
  return null;
}

export function applyDiagramStyle(doc, id) {
  const svgNS = 'http://www.w3.org/2000/svg';
  const style = doc.createElementNS(svgNS, 'style');
  style.textContent = `
    #${id} .node rect, #${id} .node polygon, #${id} .node path,
    #${id} .node circle, #${id} .node ellipse, #${id} rect.actor {
      fill: url(#${id}-card); stroke: #061c3c; stroke-width: 2;
      filter: url(#${id}-shadow);
    }
    #${id} .node text, #${id} .node tspan,
    #${id} text.actor, #${id} text.actor tspan { fill: #ffffff; }
    #${id} .cluster rect { fill: #f1f6fd; stroke: #245c9e; stroke-width: 2; }
    #${id} .cluster text, #${id} .cluster tspan { fill: #061c3c; font-weight: bold; }
    #${id} .flowchart-link, #${id} .messageLine0, #${id} .messageLine1 {
      stroke: #061c3c; stroke-width: 2;
    }
    #${id} marker path, #${id} marker polygon { fill: #061c3c !important; stroke: #061c3c !important; }
    #${id} .diagram-icon path, #${id} .diagram-icon rect, #${id} .diagram-icon ellipse {
      fill: none; stroke: #ffffff; stroke-width: 1.8; filter: none;
    }
    #${id} .messageText, #${id} .messageText tspan,
    #${id} .noteText, #${id} .noteText tspan { fill: #061c3c; }
  `;
  doc.documentElement.appendChild(style);

  for (const rect of doc.querySelectorAll('.node rect, rect.actor, .cluster rect')) {
    rect.setAttribute('rx', rect.closest('.cluster') ? '16' : '10');
    rect.setAttribute('ry', rect.closest('.cluster') ? '16' : '10');
  }

  // Keep cylinder labels inside their bodies despite estimated SVG metrics.
  for (const path of doc.querySelectorAll('.node > path.outer-path')) {
    if (!/^M0,.* a.* l0,/.test(path.getAttribute('d') || '')) continue;
    const label = path.parentElement.querySelector(':scope > g.label');
    if (!label) continue;
    const transform = label.getAttribute('transform')?.match(/translate\(([-\d.]+),/);
    const lines = Math.max(1, label.querySelectorAll('.text-outer-tspan').length);
    if (transform) label.setAttribute('transform', `translate(${transform[1]}, ${-lines * 12.15})`);
    for (const text of label.querySelectorAll('text')) text.setAttribute('style', 'text-anchor:start');
  }

  // Rectangular cards reserve left padding for an icon without moving text.
  for (const group of doc.querySelectorAll('g.node, g:has(> rect.actor)')) {
    const rect = group.querySelector(':scope > rect');
    const label = group.querySelector('text')?.textContent || '';
    const icon = iconFor(label);
    if (!rect || !icon || Number(rect.getAttribute('width')) < 140) continue;
    const text = group.querySelector('text');
    const rows = [...(text?.querySelectorAll('.text-outer-tspan') || [])];
    const labelWidth = Math.max(...(rows.length ? rows.map(row => row.textContent.length) : [label.length])) * 18 * 0.58;
    if (Number(rect.getAttribute('width')) - labelWidth < 76) continue;
    const x = Number(rect.getAttribute('x')) + 10;
    const y = Number(rect.getAttribute('y')) + Number(rect.getAttribute('height')) / 2 - 12;
    const mark = doc.createElementNS(svgNS, 'g');
    mark.setAttribute('class', 'diagram-icon');
    mark.setAttribute('transform', `translate(${x},${y})`);
    mark.setAttribute('fill', 'none');
    mark.setAttribute('stroke', '#ffffff');
    mark.setAttribute('stroke-width', '1.8');
    mark.setAttribute('stroke-linecap', 'round');
    mark.setAttribute('stroke-linejoin', 'round');
    mark.setAttribute('aria-hidden', 'true');
    mark.innerHTML = icon;
    group.appendChild(mark);
  }
}
