/* Obsidian theme behaviour — progressive enhancement only.
   Every effect here is decoration: the page must read identically with this file
   blocked, with JavaScript off, and under prefers-reduced-motion. Nothing binds
   to product state, and no network request is made.
   Reference: obsidianui.dev motifs (glowing scroll indicator, spotlight cards,
   magnetic tabs, flow-scroll reveal), reimplemented without React or Tailwind. */

/* Glowing scroll indicator. */
(() => {
  'use strict';
  const rail = document.createElement('div');
  rail.className = 'scroll-glow';
  rail.setAttribute('aria-hidden', 'true');
  const fill = document.createElement('i');
  rail.appendChild(fill);
  document.body.appendChild(rail);
  let queued = false;
  const paint = () => {
    queued = false;
    const travel = document.documentElement.scrollHeight - innerHeight;
    const ratio = travel > 0 ? Math.min(1, Math.max(0, scrollY / travel)) : 0;
    fill.style.transform = `scaleX(${ratio.toFixed(4)})`;
  };
  const schedule = () => { if (!queued) { queued = true; requestAnimationFrame(paint); } };
  addEventListener('scroll', schedule, { passive: true });
  addEventListener('resize', schedule, { passive: true });
  paint();
})();

/* Spotlight cards: the pointer lights the panel it is over. Pointer devices
   only, so a touch tap never leaves a highlight stuck on a panel. */
(() => {
  'use strict';
  if (!matchMedia('(hover: hover) and (pointer: fine)').matches) return;
  const cards = document.querySelectorAll(
    '.decision-proof,.preview,.code-box,.film-card,.product-crop,.shot-window,.scope-columns article,.sig-step'
  );
  cards.forEach(card => {
    card.classList.add('spot');
    card.addEventListener('pointermove', event => {
      const box = card.getBoundingClientRect();
      card.style.setProperty('--mx', `${event.clientX - box.left}px`);
      card.style.setProperty('--my', `${event.clientY - box.top}px`);
      card.classList.add('is-lit');
    });
    card.addEventListener('pointerleave', () => card.classList.remove('is-lit'));
  });
})();

/* Magnetic rail behind the decision tabs. home.js owns selection; this only
   follows the resulting aria-selected state, so keyboard and click agree. */
(() => {
  'use strict';
  const tabs = document.querySelector('.sample-tabs');
  if (!tabs) return;
  const glide = document.createElement('i');
  glide.className = 'tab-glide';
  glide.setAttribute('aria-hidden', 'true');
  tabs.appendChild(glide);
  tabs.classList.add('has-glide');
  const follow = () => {
    const active = tabs.querySelector('[aria-selected="true"]');
    if (!active) { glide.style.opacity = '0'; return; }
    // Measured from the rail's padding box, so container padding cannot skew it.
    const rail = tabs.getBoundingClientRect();
    const cell = active.getBoundingClientRect();
    glide.style.width = `${cell.width}px`;
    glide.style.height = `${cell.height}px`;
    glide.style.transform = `translate(${cell.left - rail.left - tabs.clientLeft}px,${cell.top - rail.top - tabs.clientTop}px)`;
    glide.style.opacity = '1';
  };
  new MutationObserver(follow).observe(tabs, {
    subtree: true, attributes: true, attributeFilter: ['aria-selected'],
  });
  if (typeof ResizeObserver === 'function') new ResizeObserver(follow).observe(tabs);
  addEventListener('resize', follow, { passive: true });
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(follow).catch(() => {});
  follow();
})();

/* Flow-scroll reveal. The hidden state is added by script and only takes effect
   inside the no-preference media query, so reduced motion and no-JS stay flat. */
(() => {
  'use strict';
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (typeof IntersectionObserver !== 'function') return;
  const blocks = document.querySelectorAll(
    '.signature-head,.story-row,.sample-layout,.workbench-copy,.workbench-shot,.film-grid,.scope-grid,.start-grid,.faq-grid'
  );
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('is-in');
      observer.unobserve(entry.target);
    });
  }, { rootMargin: '0px 0px -12% 0px', threshold: .08 });
  blocks.forEach(block => {
    // Anything already on screen at load stays visible: never hide the first view.
    if (block.getBoundingClientRect().top < innerHeight) return;
    block.classList.add('rise');
    observer.observe(block);
  });
})();
