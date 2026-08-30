const root=document.documentElement,theme=document.getElementById('theme'),sidebar=document.getElementById('sidebar');if(localStorage.jdtheme==='dark')root.classList.add('dark');function icon(){theme.textContent=root.classList.contains('dark')?'☀':'☾'}icon();theme.onclick=()=>{root.classList.toggle('dark');localStorage.jdtheme=root.classList.contains('dark')?'dark':'light';icon()};document.getElementById('menu').onclick=()=>sidebar.classList.toggle('open');document.querySelectorAll('.nav a').forEach(a=>a.onclick=()=>sidebar.classList.remove('open'));

const evidenceDate=value=>value?new Intl.DateTimeFormat(undefined,{year:'numeric',month:'short',day:'numeric'}).format(new Date(value)):'Pending';
fetch('/api/engineering-evidence').then(response=>{if(!response.ok)throw new Error('Evidence unavailable');return response.json()}).then(data=>{
  document.getElementById('evidenceRepos').textContent=data.github.repositories;
  document.getElementById('evidenceRecent').textContent=data.github.recentlyUpdated;
  document.getElementById('evidenceLanguages').textContent=data.github.languages;
  document.getElementById('evidenceLatest').textContent=data.github.latestRepository;
  document.getElementById('evidenceDeploy').textContent=evidenceDate(data.cloudflare.deployedAt);
  document.getElementById('evidenceEdge').textContent=data.cloudflare.edge;
  document.getElementById('evidenceStatus').textContent=`Automatically refreshed ${evidenceDate(data.refreshedAt)} from GitHub and Cloudflare`;
}).catch(()=>{document.getElementById('evidenceStatus').textContent='Verified fallback evidence · live refresh temporarily unavailable'});
