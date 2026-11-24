import{U as c,y as h,O as u,r as w,u as y,q as O,m as C,z as k,P as f,V as A}from"./index-ChEn0GHg.js";/**
 * @license lucide-vue-next v0.552.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const p=e=>e.replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase(),P=e=>e.replace(/^([A-Z])|[\s-_]+(\w)/g,(r,n,t)=>t?t.toUpperCase():n.toLowerCase()),S=e=>{const r=P(e);return r.charAt(0).toUpperCase()+r.slice(1)},b=(...e)=>e.filter((r,n,t)=>!!r&&r.trim()!==""&&t.indexOf(r)===n).join(" ").trim(),g=e=>e==="";/**
 * @license lucide-vue-next v0.552.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */var i={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor","stroke-width":2,"stroke-linecap":"round","stroke-linejoin":"round"};/**
 * @license lucide-vue-next v0.552.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const x=({name:e,iconNode:r,absoluteStrokeWidth:n,"absolute-stroke-width":t,strokeWidth:o,"stroke-width":s,size:a=i.width,color:m=i.stroke,...l},{slots:d})=>c("svg",{...i,...l,width:a,height:a,stroke:m,"stroke-width":g(n)||g(t)||n===!0||t===!0?Number(o||s||i["stroke-width"])*24/Number(a):o||s||i["stroke-width"],class:b("lucide",l.class,...e?[`lucide-${p(S(e))}-icon`,`lucide-${p(e)}`]:["lucide-icon"])},[...r.map(v=>c(...v)),...d.default?[d.default()]:[]]);/**
 * @license lucide-vue-next v0.552.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const U=(e,r)=>(n,{slots:t,attrs:o})=>c(x,{...o,...n,iconNode:r,name:e},t);function j(e){return C()?(k(e),!0):!1}function _(e){if(!u(e))return w(e);const r=new Proxy({},{get(n,t,o){return y(Reflect.get(e.value,t,o))},set(n,t,o){return u(e.value[t])&&!u(o)?e.value[t].value=o:e.value[t]=o,!0},deleteProperty(n,t){return Reflect.deleteProperty(e.value,t)},has(n,t){return Reflect.has(e.value,t)},ownKeys(){return Object.keys(e.value)},getOwnPropertyDescriptor(){return{enumerable:!0,configurable:!0}}});return w(r)}function I(e){return _(h(e))}function B(e,...r){const n=r.flat(),t=n[0];return I(()=>Object.fromEntries(typeof t=="function"?Object.entries(f(e)).filter(([o,s])=>!t(A(s),o)):Object.entries(f(e)).filter(o=>!n.includes(o[0]))))}const D=typeof window<"u"&&typeof document<"u";typeof WorkerGlobalScope<"u"&&globalThis instanceof WorkerGlobalScope;const G=e=>typeof e<"u",$=Object.prototype.toString,T=e=>$.call(e)==="[object Object]",V=()=>{},Z=E();function E(){var e,r;return D&&((e=window?.navigator)==null?void 0:e.userAgent)&&(/iP(?:ad|hone|od)/.test(window.navigator.userAgent)||((r=window?.navigator)==null?void 0:r.maxTouchPoints)>2&&/iPad|Macintosh/.test(window?.navigator.userAgent))}function q(e){return Array.isArray(e)?e:[e]}function K(e,r,n){return O(e,r,{...n,immediate:!0})}export{G as a,D as b,U as c,j as d,T as e,Z as i,V as n,B as r,q as t,K as w};
