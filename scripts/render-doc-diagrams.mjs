// Render editable diagram sources without requiring a browser.
// SVG text metrics are estimated; review exported images after source changes.
import { JSDOM } from '../web/node_modules/jsdom/lib/api.js';
import { writeFileSync,readFileSync,mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
const dom=new JSDOM('<html><body></body></html>',{pretendToBeVisual:true});
globalThis.window=dom.window; globalThis.document=dom.window.document;
globalThis.CSSStyleSheet=dom.window.CSSStyleSheet;
const proto=dom.window.SVGElement.prototype;
proto.getBBox=function(){
 const tag=this.tagName.toLowerCase();const n=k=>Number.parseFloat(this.getAttribute(k))||0;
 if(['style','defs','marker','script'].includes(tag))return{x:0,y:0,width:0,height:0};
 if(tag==='rect')return{x:n('x'),y:n('y'),width:n('width'),height:n('height')};
 if(['circle','ellipse'].includes(tag)){const rx=n('rx')||n('r'),ry=n('ry')||n('r');return{x:n('cx')-rx,y:n('cy')-ry,width:rx*2,height:ry*2};}
 if(['text','tspan'].includes(tag)){const fs=18;const lines=Array.from(this.querySelectorAll('.text-outer-tspan')).map(x=>x.textContent);const text=lines.length?lines:[this.textContent||''];return{x:n('x'),y:n('y')-fs,width:Math.max(1,...text.map(x=>x.length*fs*.58)),height:fs*1.35*Math.max(1,lines.length)};}
 if(['polygon','polyline'].includes(tag)){const v=(this.getAttribute('points')||'').match(/-?\d+(?:\.\d+)?/g)?.map(Number)||[];const xs=v.filter((_,i)=>i%2===0),ys=v.filter((_,i)=>i%2===1);return{x:Math.min(0,...xs),y:Math.min(0,...ys),width:Math.max(0,...xs)-Math.min(0,...xs),height:Math.max(0,...ys)-Math.min(0,...ys)};}
 if(tag==='line')return{x:Math.min(n('x1'),n('x2')),y:Math.min(n('y1'),n('y2')),width:Math.abs(n('x2')-n('x1')),height:Math.abs(n('y2')-n('y1'))};
 if(tag==='path'){const v=(this.getAttribute('d')||'').match(/-?\d+(?:\.\d+)?/g)?.map(Number)||[];const xs=v.filter((_,i)=>i%2===0),ys=v.filter((_,i)=>i%2===1);return{x:Math.min(0,...xs),y:Math.min(0,...ys),width:Math.max(0,...xs)-Math.min(0,...xs),height:Math.max(0,...ys)-Math.min(0,...ys)};}
 const boxes=Array.from(this.children).filter(x=>x.getBBox).map(x=>{const box=x.getBBox();const m=(x.getAttribute('transform')||'').match(/translate\(\s*([-\d.]+)[ ,]+([-\d.]+)/);return{...box,x:box.x+(m?Number(m[1]):0),y:box.y+(m?Number(m[2]):0)};}).filter(x=>x.width||x.height);
 if(!boxes.length)return{x:0,y:0,width:0,height:0};
 const x=Math.min(...boxes.map(b=>b.x)),y=Math.min(...boxes.map(b=>b.y));return{x,y,width:Math.max(...boxes.map(b=>b.x+b.width))-x,height:Math.max(...boxes.map(b=>b.y+b.height))-y};
};
proto.getBoundingClientRect=function(){const b=this.getBBox();return{...b,top:b.y,left:b.x,right:b.x+b.width,bottom:b.y+b.height};};
proto.getComputedTextLength=function(){return this.getBBox().width;};
const {default:mermaid}=await import('../web/node_modules/mermaid/dist/mermaid.core.mjs');
mermaid.initialize({startOnLoad:false,theme:'base',fontFamily:'DejaVu Sans',htmlLabels:false,themeVariables:{edgeLabelBackground:'#f7faff',clusterBkg:'#eef4fc',clusterBorder:'#4775b3',tertiaryColor:'#eef4fc',noteBkgColor:'#edf4fc',noteBorderColor:'#4775b3',actorBkg:'#153f73',actorTextColor:'#ffffff',actorBorder:'#123560',primaryColor:'#e2edfc',primaryTextColor:'#061c3c',primaryBorderColor:'#1c579c',lineColor:'#123560',background:'#f7faff',fontSize:'18px'},flowchart:{htmlLabels:false,wrappingWidth:400,rankSpacing:120,nodeSpacing:70}});
const manifests=process.argv.slice(2).length?process.argv.slice(2):['docs/diagrams/manifest.json'];
const records=manifests.flatMap(p=>JSON.parse(readFileSync(p,'utf8')));
const escape=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
let i=0;
for(const record of records){
 let code=readFileSync(record.source,'utf8');
 if(code.trim().startsWith('sequenceDiagram')) code=code.replace(/;/g,'#59;');
 const id='figure'+i++;
 let {svg}=await mermaid.render(id,code);
 const parsed=await mermaid.mermaidAPI.getDiagramFromText(code);
 const rawLabels=new Map((parsed.db.getEdges?.()||[]).map(e=>[e.id,e.text||'']));
 const svgDoc=new dom.window.DOMParser().parseFromString(svg,'image/svg+xml');
 for(const row of svgDoc.querySelectorAll('.text-outer-tspan'))row.textContent=row.textContent;
 for(const edge of svgDoc.querySelectorAll('g.edgeLabel')){
  let rows=[...edge.querySelectorAll('.text-outer-tspan')].map(r=>r.textContent);
  const key=edge.querySelector('[data-id]')?.getAttribute('data-id');
  if(rawLabels.has(key)){
   const text=rawLabels.get(key).replace(/<br\s*\/?\s*>/gi,'\n').replace(/\\n/g,'\n');
   const el=dom.window.document.createElement('div');el.innerHTML=text;
   rows=el.textContent.split('\n').flatMap(line=>{
    const result=[];let current='';
    for(const word of line.split(/\s+/)){if(current&&current.length+word.length>40){result.push(current);current='';}current+=(current?' ':'')+word;}
    if(current)result.push(current);return result;
   });
  }
  if(!rows.length)continue;
  const width=Math.max(...rows.map(r=>r.length*18*.58)),height=rows.length*24;
  edge.innerHTML=`<rect x="${-width/2-8}" y="${-height/2-6}" width="${width+16}" height="${height+12}" rx="4" style="fill:#f7faff;opacity:1;fill-opacity:1;stroke:none"/><text text-anchor="middle" fill="#061c3c" font-family="DejaVu Sans" font-size="18">${rows.map((r,j)=>`<tspan x="0" y="${-height/2+18+j*24}">${escape(r)}</tspan>`).join('')}</text>`;
 }
 for(const label of svgDoc.querySelectorAll('.loopText, .loopText tspan, .sectionTitle, .sectionTitle tspan'))label.setAttribute('style','fill:#061c3c');
 svg=new dom.window.XMLSerializer().serializeToString(svgDoc.documentElement);
 const [,minX,minY,width,height]=svg.match(/viewBox="([\-\d.]+) ([\-\d.]+) ([\d.]+) ([\d.]+)"/).map(Number);
 const w=Math.max(width+96,record.title.length*17+96,720),h=height+164;
 const contents=svg.replace(/^<svg[^>]*>/,'').replace(/<\/svg>$/,'');
 const framed=`<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><rect width="${w}" height="${h}" fill="#f7faff"/><rect x="16" y="16" width="${w-32}" height="${h-32}" rx="18" fill="#ffffff" stroke="#dce6f3"/><text x="48" y="58" font-family="DejaVu Sans" font-size="28" font-weight="bold" fill="#061c3c">${escape(record.title)}</text><text x="48" y="86" font-family="DejaVu Sans" font-size="14" fill="#315f99">Veyport · Reference diagram</text><svg id="${id}" overflow="visible" x="${(w-width)/2}" y="112" width="${width}" height="${height}" viewBox="${minX} ${minY} ${width} ${height}">${contents}</svg></svg>`;
 const svgPath=record.image.replace(/\.png$/,'.svg');
 mkdirSync(dirname(record.image),{recursive:true});writeFileSync(svgPath,framed);
 const run=spawnSync('python3',['scripts/svg-to-png.py',svgPath,record.image],{encoding:'utf8'});
 if(run.status!==0)throw new Error(run.stderr||run.stdout);
 console.log(run.stdout.trim());
}
dom.window.close();
