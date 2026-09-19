// Run with: node --test tests/frontend.test.cjs
// Small DOM doubles exercise response rendering and async cleanup; CI also runs
// the real Docker application in Chromium (see browser smoke test).
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];

function app(fetch=async()=>response({proven:false,steps:[]})){
  const nodes=new Map(), buttons=[];
  class Element{
    constructor(){ this.value=''; this.dataset={}; this.style={}; this.children=[]; this.className=''; this.disabled=false; this.innerHTML=''; this.textContent=''; this.listeners={}; this.classList={add(){},remove(){}}; }
    appendChild(node){
      this.children.push(node);
      const target=node.innerHTML.match(/data-t="([^"]+)"/);
      if(target){ const button=new Element(); button.dataset.t=target[1]; buttons.push(button); }
    }
    replaceChildren(...children){ this.children=children; this.innerHTML=''; this.textContent=children.map(c=>c.textContent).join(''); }
    querySelector(){ return this.detail ||= new Element(); }
    querySelectorAll(){ return []; }
    addEventListener(name,fn){ this.listeners[name]=fn; }
    setAttribute(name,value){ this[name]=value; }
    scrollIntoView(){}
  }
  const get=id=>{ if(!nodes.has(id)) nodes.set(id,new Element()); return nodes.get(id); };
  const context=vm.createContext({
    document:{getElementById:get,createElement:()=>new Element(),querySelectorAll:selector=>selector==='.runbtn'?buttons:[],head:new Element()},
    window:{},localStorage:{getItem:()=>null},URL,AbortController,setTimeout,clearTimeout,fetch,
  });
  vm.runInContext(script,context,{filename:'index.html'});
  return {context,get,buttons,run:expression=>vm.runInContext(expression,context)};
}
function response(data,status=200){ return {ok:status>=200 && status<300,status,text:async()=>JSON.stringify(data)}; }

test('API text is escaped in metrics, sources, heuristics, and steps',()=>{
  const a=app(); a.context.payload={proven:true,firstViolated:'<img src=x onerror=alert(1)>',ms:'<svg/onload=alert(1)>',steps:[{step:'scan',title:'<b>untrusted</b>',strategy:'<img src=x>'},{step:'verify',checkAll_after:{allHold:false,firstViolated:'<svg/onload=1>'}}],heuristics:[{title:'<script>x</script>',why:123}],target_src:'</pre><img src=x>'};
  const rendered=a.run('metricsHtml(payload,true)+srcHtml(payload)+heuristicsHtml(payload)');
  assert.doesNotMatch(rendered,/<img|<svg|<script/);
  assert.match(rendered,/&lt;img/);
  a.run("renderSteps(document.getElementById('steps'),payload)");
  assert.doesNotMatch(a.get('steps').innerHTML,/<img|<svg|<b>untrusted/);
  assert.match(a.get('steps').innerHTML,/&lt;b&gt;untrusted/);
});

test('missing steps do not claim completion and reset removes stale labels',()=>{
  const a=app();
  a.run("renderSteps(document.getElementById('steps'),{proven:true,steps:[]},'OpenVault')");
  assert.doesNotMatch(a.get('steps').innerHTML,/on done/);
  assert.match(a.get('steps').innerHTML,/실행 기록 없음/);
  a.get('st-OpenVault-0').querySelector('.d').textContent='old result';
  a.run("resetSteps('OpenVault')");
  assert.equal(a.get('st-OpenVault-0').querySelector('.d').textContent,a.run('STEP_DEFS[0].label'));
});

test('NOT PROVEN does not claim safety or invent zero balances',async()=>{
  const a=app(async()=>response({proven:false,note:'no pattern',steps:[]}));
  await a.run("run('SafeVault')");
  assert.equal(a.get('v-SafeVault').textContent,'NOT PROVEN');
  assert.doesNotMatch(a.get('out-SafeVault').innerHTML,/불변식 유지|오탐 없음|0 ETH/);
  assert.match(a.get('out-SafeVault').innerHTML,/안전을 보장하지/);
  assert.equal(a.get('runAll').disabled,false);
});

test('non-JSON HTTP failures restore controls and allow a successful rerun',async()=>{
  let calls=0;
  const a=app(async()=>++calls===1 ? {ok:false,status:502,text:async()=>'<h1>Bad gateway</h1>'} : response({proven:true,steps:[{step:'verify'}]}));
  await a.run("run('OpenVault')");
  assert.equal(a.get('v-OpenVault').textContent,'ERROR');
  assert.match(a.get('out-OpenVault').textContent,/HTTP 502/);
  assert.equal(a.buttons.find(b=>b.dataset.t==='OpenVault').disabled,false);
  await a.run("run('OpenVault')");
  assert.equal(a.get('v-OpenVault').textContent,'PROVEN');
});

test('duplicate target clicks share one request',async()=>{
  let resolve,calls=0;
  const a=app(()=>{ calls++; return new Promise(done=>{resolve=done;}); });
  const one=a.run("run('OpenVault')"),two=a.run("run('OpenVault')");
  assert.equal(calls,1); assert.equal(one,two);
  assert.equal(a.get('runAll').disabled,true);
  resolve(response({proven:true,steps:[]})); await one;
  assert.equal(a.get('runAll').disabled,false);
});

test('API errors render as text and custom controls recover',async()=>{
  const payload='<img src=x onerror=alert(1)>';
  const a=app(async()=>response({error:payload}));
  a.get('c-contract').value='contract Example {}';
  await a.run('runCustom()');
  assert.equal(a.get('v-custom').textContent,'ERROR');
  assert.equal(a.get('out-custom').textContent,payload);
  assert.equal(a.get('out-custom').innerHTML,'');
  assert.equal(a.get('runCustom').disabled,false);
});

test('dependency-stage failure also restores custom controls',async()=>{
  const a=app(); a.get('c-contract').value='import "./Needed.sol"; contract Example {}';
  a.run("runResolve=async()=>{throw new Error('dependency failure')}");
  await a.run('runCustom()');
  assert.equal(a.get('runCustom').disabled,false);
  assert.equal(a.get('v-custom').textContent,'ERROR');
});

test('request timeout aborts hung transport',async()=>{
  const a=app((url,{signal})=>new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('aborted')))));
  await assert.rejects(a.run("request('/api/prove',{},5)"),/요청 시간이/);
});

test('imports preserve URL strings, support aliases, and ignore comments',()=>{
  const a=app(); a.context.source='// import "fake.sol";\nimport "https://example.test/A.sol";\nimport "./B.sol" as B; /* import "fake2.sol"; */';
  assert.deepEqual(Array.from(a.run('detectImports(source)')),['https://example.test/A.sol','./B.sol']);
});

test('uploaded dependencies are resolved without any network request',async()=>{
  const a=app(async()=>{throw new Error('unexpected network');});
  a.run('_attached["@example/A.sol"]="pragma solidity ^0.8.0; contract A {}"');
  const data=await a.run('resolveAllDeps(\'import "@example/A.sol";\',"latest")');
  assert.equal(data.unresolved.length,0);
  assert.match(data.sources['attach:@example/A.sol'],/contract A/);
});

test('import names cannot escape dependency panel attributes',async()=>{
  const a=app(); a.context.source='import \'./evil"><img src=x>.sol\';';
  await a.run('runResolve(source)');
  assert.doesNotMatch(a.get('deps-list').innerHTML,/<img/);
  assert.match(a.get('deps-list').innerHTML,/&lt;img/);
});
