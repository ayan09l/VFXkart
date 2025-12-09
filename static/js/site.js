// --- auth + seller helpers (password strength, drag-drop logo, demo quickseed helper) ---
document.addEventListener('DOMContentLoaded', () => {
  // Password strength meter (simple)
  const pwInputs = document.querySelectorAll('input[type="password"].pw-strength');
  pwInputs.forEach(input => {
    // create meter element
    const meter = document.createElement('div');
    meter.className = 'pw-meter mt-1 h-2 rounded bg-white/6 overflow-hidden';
    meter.innerHTML = '<div class="pw-fill h-full transition-all" style="width:0%"></div>';
    input.parentNode.insertBefore(meter, input.nextSibling);

    input.addEventListener('input', () => {
      const v = input.value || '';
      let score = 0;
      if (v.length >= 8) score += 1;
      if (/[A-Z]/.test(v)) score += 1;
      if (/[0-9]/.test(v)) score += 1;
      if (/[^A-Za-z0-9]/.test(v)) score += 1;
      const pct = Math.min(100, score * 25);
      const fill = meter.querySelector('.pw-fill');
      fill.style.width = pct + '%';
      if (pct < 50) fill.style.background = 'linear-gradient(90deg,#ef4444,#f97316)';
      else if (pct < 75) fill.style.background = 'linear-gradient(90deg,#f59e0b,#f97316)';
      else fill.style.background = 'linear-gradient(90deg,#10b981,#06b6d4)';
    });
  });

  // Drag & Drop file upload for seller logo (works with <input id="logoInput">)
  const dropZones = document.querySelectorAll('.dropzone');
  dropZones.forEach(z => {
    const input = z.querySelector('input[type="file"]');
    const preview = z.querySelector('.drop-preview');
    function showPreview(file){
      if(!file) { preview.innerHTML = '<div class="text-sm text-slate-400">No logo</div>'; return; }
      const url = URL.createObjectURL(file);
      preview.innerHTML = `<img src="${url}" alt="logo" class="max-h-20 object-contain rounded"/>`;
    }
    z.addEventListener('dragover', (e)=>{
      e.preventDefault(); z.classList.add('drop-over');
    });
    z.addEventListener('dragleave', ()=> z.classList.remove('drop-over'));
    z.addEventListener('drop', (e)=>{
      e.preventDefault(); z.classList.remove('drop-over');
      const f = (e.dataTransfer.files && e.dataTransfer.files[0]) || null;
      if(f && input) { input.files = e.dataTransfer.files; showPreview(f); }
    });
    if(input){
      input.addEventListener('change', ()=> {
        const f = input.files && input.files[0];
        showPreview(f);
      });
    }
    // initial
    showPreview(null);
  });

  // Quick demo helper: when there is a button with id="seedDemoBtn" it'll POST to /seed-demo (only if present)
  const seedBtn = document.getElementById('seedDemoBtn');
  if(seedBtn){
    seedBtn.addEventListener('click', async (ev)=>{
      ev.preventDefault();
      seedBtn.disabled = true; seedBtn.textContent = 'Seeding...';
      try{
        const res = await fetch('/seed-demo', { method: 'POST', headers:{'X-Requested-With':'XMLHttpRequest'} });
        if(res.ok){
          seedBtn.textContent = 'Done — Reload';
          location.reload();
        } else {
          seedBtn.disabled = false; seedBtn.textContent = 'Seed demo';
          alert('Seeding failed: ' + res.status);
        }
      }catch(err){
        seedBtn.disabled = false; seedBtn.textContent = 'Seed demo';
        alert('Seeding error: ' + err.message);
      }
    });
  }
});
