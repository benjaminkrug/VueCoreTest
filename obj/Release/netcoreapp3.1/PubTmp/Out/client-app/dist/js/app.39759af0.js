(function(t){function e(e){for(var r,s,i=e[0],c=e[1],u=e[2],p=0,d=[];p<i.length;p++)s=i[p],Object.prototype.hasOwnProperty.call(o,s)&&o[s]&&d.push(o[s][0]),o[s]=0;for(r in c)Object.prototype.hasOwnProperty.call(c,r)&&(t[r]=c[r]);l&&l(e);while(d.length)d.shift()();return a.push.apply(a,u||[]),n()}function n(){for(var t,e=0;e<a.length;e++){for(var n=a[e],r=!0,i=1;i<n.length;i++){var c=n[i];0!==o[c]&&(r=!1)}r&&(a.splice(e--,1),t=s(s.s=n[0]))}return t}var r={},o={app:0},a=[];function s(e){if(r[e])return r[e].exports;var n=r[e]={i:e,l:!1,exports:{}};return t[e].call(n.exports,n,n.exports,s),n.l=!0,n.exports}s.m=t,s.c=r,s.d=function(t,e,n){s.o(t,e)||Object.defineProperty(t,e,{enumerable:!0,get:n})},s.r=function(t){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},s.t=function(t,e){if(1&e&&(t=s(t)),8&e)return t;if(4&e&&"object"===typeof t&&t&&t.__esModule)return t;var n=Object.create(null);if(s.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:t}),2&e&&"string"!=typeof t)for(var r in t)s.d(n,r,function(e){return t[e]}.bind(null,r));return n},s.n=function(t){var e=t&&t.__esModule?function(){return t["default"]}:function(){return t};return s.d(e,"a",e),e},s.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)},s.p="/";var i=window["webpackJsonp"]=window["webpackJsonp"]||[],c=i.push.bind(i);i.push=e,i=i.slice();for(var u=0;u<i.length;u++)e(i[u]);var l=c;a.push([0,"chunk-vendors"]),n()})({0:function(t,e,n){t.exports=n("56d7")},"0262":function(t,e,n){},"160c":function(t,e,n){},"2c84":function(t,e,n){},"2cb4":function(t,e,n){"use strict";n("36ec")},"33ef":function(t,e,n){},"36ec":function(t,e,n){},5340:function(t,e,n){"use strict";n("0262")},"56d7":function(t,e,n){"use strict";n.r(e);n("e260"),n("e6cf"),n("cca6"),n("a79d");var r=n("2b0e"),o=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"bild-123"},[n("AppComponent")],1)},a=[],s=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"app"},[n("a",{attrs:{href:"#"},on:{click:function(e){return t.$oidc.signIn()}}},[t._v("Signin")]),t.$oidc.isAuthenticated?n("a",{attrs:{href:"#"},on:{click:function(e){return t.$oidc.signOut()}}},[t._v("Signout")]):t._e(),n("NavWrapper"),n("div",{staticClass:"app-router"},[n("router-view")],1)],1)},i=[],c=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"nav-bar",on:{mouseover:function(e){t.active=!1},mouseleave:function(e){t.active=!0}}},[n("div",[t.active?n("div",[t._v(" - ")]):n("div",[t._v(" > "),n("NavBar",{staticClass:"nav"})],1)])])},u=[],l=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"inner-nav-bar"},[n("NavButton",{staticClass:"inner-button",attrs:{link:"/login",text:"Login"}}),n("NavButton",{staticClass:"inner-button",attrs:{link:"/registration",text:"Registrieren"}}),n("TestButton",{staticClass:"inner-button"}),n("NavButton",{staticClass:"inner-button",attrs:{link:"/test/bild",text:"Bild"}}),n("button",{on:{click:function(e){return e.preventDefault(),t.authLogin(e)}}},[t._v("log")])],1)},p=[],d=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"nav-button-1"},[n("router-link",{staticClass:"nav-link",attrs:{to:"/test"}},[t._v("Test")])],1)},f=[],v={name:"NavButton",components:{},props:{},data:function(){return{}},methods:{}},m=v,h=(n("cf27"),n("2877")),b=Object(h["a"])(m,d,f,!1,null,"778dfe6a",null),g=b.exports,_=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"nav-button-1"},[n("router-link",{staticClass:"nav-link",attrs:{to:t.link}},[t._v(t._s(t.text))])],1)},w=[],x={name:"NavButton1",components:{},props:{link:String,text:String},data:function(){return{}},methods:{}},y=x,C=(n("fbdc"),Object(h["a"])(y,_,w,!1,null,"71218c38",null)),O=C.exports,j={name:"NavBar",components:{TestButton:g,NavButton:O},props:{hover:Boolean},data:function(){return{}},methods:{authLogin:function(){this.$auth.loginWithRedirect()}}},k=j,B=(n("8073"),Object(h["a"])(k,l,p,!1,null,"b6a6183e",null)),N=B.exports,$={name:"NavWrapper",components:{NavBar:N},data:function(){return{active:!0}},methods:{mouseOver:function(){this.active=!this.active}}},P=$,S=(n("aba0"),Object(h["a"])(P,c,u,!1,null,"05e2c744",null)),W=S.exports,E={name:"AppComponent",components:{NavWrapper:W},data:function(){return{}},methods:{}},T=E,A=(n("5772"),Object(h["a"])(T,s,i,!1,null,"49b7f322",null)),I=A.exports,L={name:"App",components:{AppComponent:I},data:function(){return{}},methods:{}},R=L,U=(n("9cff"),Object(h["a"])(R,o,a,!1,null,"74d024c1",null)),H=U.exports,K=n("8c4f"),M=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"login-background"},[t._v(" Login ")])},q=[],z={name:"Login",props:{},data:function(){return{username:"Benutzername",password:"Password"}},methods:{},computed:{}},Y=z,D=(n("c485"),Object(h["a"])(Y,M,q,!1,null,"6ead501a",null)),J=D.exports,G=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"login-background"},[n("form",{staticClass:"login"},[n("h1",[t._v("Registrieren")]),n("label",[t._v("Benutzername")]),n("input",{directives:[{name:"model",rawName:"v-model",value:t.username,expression:"username"}],attrs:{required:"",type:"text"},domProps:{value:t.username},on:{input:function(e){e.target.composing||(t.username=e.target.value)}}}),n("label",[t._v("Passwort")]),n("input",{directives:[{name:"model",rawName:"v-model",value:t.password,expression:"password"}],attrs:{required:"",type:"password"},domProps:{value:t.password},on:{input:function(e){e.target.composing||(t.password=e.target.value)}}}),n("label",[t._v("Passwort Wiederholen")]),n("input",{directives:[{name:"model",rawName:"v-model",value:t.passwordWiederholung,expression:"passwordWiederholung"}],attrs:{required:"",type:"password"},domProps:{value:t.passwordWiederholung},on:{input:function(e){e.target.composing||(t.passwordWiederholung=e.target.value)}}}),n("hr"),n("button",{attrs:{type:"submit",disabled:!t.passwordIsSame},on:{click:t.registrieren}},[t._v("Registrieren")])])])},V=[],F=(n("498a"),n("d442")),Q=n.n(F),X=n("2652"),Z=n.n(X),tt=n("bc3a"),et=n.n(tt),nt={name:"Registration",props:{},data:function(){return{username:"Benutzername",password:"",passwordWiederholung:""}},methods:{encrypt:function(t,e){var n=new Z.a;n.setPublicKey(e);var r=n.encrypt(t),o=btoa(r);return o},registrieren:function(){var t=this,e="",n="",r=this.password;et.a.post("/User/Registration/".concat(this.username,"/PublicKey")).then((function(o){e=o.data.replac("-----BEGIN PUBLIC KEY-----","").replac("-----END PUBLIC KEY-----","").trim(),n=t.encrypt(r,e),et.a.post("/User/Registration/".concat(t.username),{passHash:n}).then((function(t){e=t.data}))}))}},computed:{passHash:function(){return Q()(this.password)},passwordIsSame:function(){return!!this.password&&this.password==this.passwordWiederholung}}},rt=nt,ot=(n("5340"),Object(h["a"])(rt,G,V,!1,null,"f675622e",null)),at=ot.exports,st=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"hello"},[n("h1",[t._v(t._s(t.msg))]),t._v(" "+t._s(t.test)+" "),n("button",{on:{click:t.backendTest}},[t._v(" hallo ")]),t._v(" "+t._s(t.getUserNam())+" ")])},it=[],ct={name:"HelloWorld",props:{msg:String},data:function(){return{test:"test"}},methods:{backendTest:function(){var t=this;et.a.get("/User").then((function(e){t.test=e.data}))},getUserNam:function(){return this.$auth.user}}},ut=ct,lt=(n("2cb4"),Object(h["a"])(ut,st,it,!1,null,"79fb54f8",null)),pt=lt.exports,dt=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"test"},[n("div",[n("HelloWorld",{attrs:{msg:"Welcome to Your Vue.js App"}}),t._v(" "+t._s(t.text)+" "+t._s(t.text1)+" "+t._s(t.password)+" ")],1)])},ft=[],vt={name:"AppComponent",components:{HelloWorld:pt},data:function(){return{active:!0,text:"testString",text1:"rsaString",password:"testString"}},methods:{}},mt=vt,ht=(n("692e"),Object(h["a"])(mt,dt,ft,!1,null,"74a09bbe",null)),bt=ht.exports,gt=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div")},_t=[],wt={name:"ImageTest",components:{},data:function(){return{}},methods:{}},xt=wt,yt=Object(h["a"])(xt,gt,_t,!1,null,"56903444",null),Ct=yt.exports,Ot={template:"<div>bar</div>"};r["a"].use(K["a"]);var jt=new K["a"]({mode:"history",base:"/",routes:[{path:"/login",component:J},{path:"/registration",component:at},{path:"/test/helloworld",component:pt},{path:"/test",component:bt},{path:"/test/bild",component:Ct},{path:"/bar",component:Ot},{path:"/profile",name:"profile",component:Ct}]}),kt=jt,Bt=n("3526");r["a"].config.productionTip=!1;var Nt="https://localhost:8080/",$t=Object(Bt["b"])("main",Bt["a"].Window,Nt,{authority:"https://localhost:44367/",redirect_uri:"http://localhost:8080/Home/SignIn",client_id:"client_id_js",response_type:"code",scope:"openid"});r["a"].prototype.$oidc=$t,$t.startup().then((function(t){t&&new r["a"]({router:kt,render:function(t){return t(H)},components:{App:H}}).$mount("#app")}))},5772:function(t,e,n){"use strict";n("82d3")},"692e":function(t,e,n){"use strict";n("160c")},8073:function(t,e,n){"use strict";n("2c84")},"82d3":function(t,e,n){},"8c4e":function(t,e,n){},"8f35":function(t,e,n){},"965f":function(t,e,n){},"9cff":function(t,e,n){"use strict";n("ff8d")},aba0:function(t,e,n){"use strict";n("965f")},c485:function(t,e,n){"use strict";n("33ef")},cf27:function(t,e,n){"use strict";n("8f35")},fbdc:function(t,e,n){"use strict";n("8c4e")},ff8d:function(t,e,n){}});
//# sourceMappingURL=app.39759af0.js.map