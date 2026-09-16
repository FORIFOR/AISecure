(() => {
  'use strict';
  const ja = document.documentElement.lang === 'ja';
  const tabs = [...document.querySelectorAll('[data-sample-tab]')];
  const panels = [...document.querySelectorAll('[data-sample-panel]')];
  function select(tab, focus = false) {
    tabs.forEach(t => { const active=t===tab; t.setAttribute('aria-selected',String(active)); t.tabIndex=active?0:-1; });
    panels.forEach(p => { p.hidden=p.id!==tab.getAttribute('aria-controls'); });
    if(focus)tab.focus();
  }
  tabs.forEach((tab,index)=>{
    tab.addEventListener('click',()=>select(tab));
    tab.addEventListener('keydown',event=>{
      let next;
      if(event.key==='ArrowRight')next=(index+1)%tabs.length;
      else if(event.key==='ArrowLeft')next=(index-1+tabs.length)%tabs.length;
      else if(event.key==='Home')next=0;
      else if(event.key==='End')next=tabs.length-1;
      else return;
      event.preventDefault();select(tabs[next],true);
    });
  });
  const copy=document.getElementById('copy-command');
  if(copy)copy.addEventListener('click',async()=>{
    const status=document.getElementById('copy-status');
    try{await navigator.clipboard.writeText(document.getElementById('install-command').textContent);status.textContent=ja?'起動コマンドをコピーしました。':'Startup commands copied.';}
    catch{status.textContent=ja?'コピーできませんでした。コマンドを選択してコピーしてください。':'Select and copy the commands manually.';}
  });
})();

/* One signature motion only: input -> check -> verdict. */
(() => {
  'use strict';
  const signature=document.querySelector('[data-signature]');
  if(!signature)return;
  if(matchMedia('(prefers-reduced-motion: reduce)').matches){signature.classList.add('is-visible');return;}
  let done=false;
  const observer=new IntersectionObserver(entries=>{
    if(done)return;
    if(entries.some(entry=>entry.isIntersecting)){done=true;signature.classList.add('is-visible');observer.disconnect();}
  },{threshold:.45});
  observer.observe(signature);
})();

/* Product film: user initiated, static until requested. */
(() => {
  'use strict';
  const video=document.getElementById('product-film');
  const cover=document.querySelector('.film-splash');
  if(!video)return;
  if(cover){video.addEventListener('play',()=>{cover.hidden=true;});}
  document.querySelectorAll('[data-play-film]').forEach(control=>control.addEventListener('click',async()=>{
    const status=document.getElementById('film-status');
    try{if(video.ended)video.currentTime=0;await video.play();if(status)status.textContent='';}
    catch{if(cover)cover.hidden=true;if(status)status.textContent=document.documentElement.lang==='ja'?'映像内の再生ボタンを押してください。':'Use the play control on the video.';}
  }));
})();
