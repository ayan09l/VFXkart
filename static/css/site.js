// tiny helpers for UX
document.addEventListener('click', (e)=>{
  const el = e.target.closest('button.link.danger');
  if(el && !confirm('Are you sure?')) e.preventDefault();
});
