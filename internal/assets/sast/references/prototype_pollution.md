---
name: prototype_pollution
description: Prototype pollution in JavaScript/TypeScript — Object.prototype manipulation leading to RCE, authentication bypass, or DoS
---

# Prototype Pollution

Prototype pollution occurs when attacker-controlled keys (e.g. `__proto__`, `constructor`, `prototype`) are merged into a target object without sanitization, corrupting `Object.prototype` and affecting every object in the runtime. Severity ranges from property injection (auth bypass, privilege escalation) to Remote Code Execution when polluted properties flow into `eval`, `child_process.exec`, or template sinks.

## Where to Look

**Languages / Runtimes**
- Node.js / Bun / Deno — any deep-merge, clone, or path-set utility

**Frameworks with Known Gadgets**
- Express (res.render template sinks), Handlebars/EJS/Pug (template engines)
- Lodash <4.17.21, merge-deep, deepmerge, flat, jquery-deparam, hoek

**Common Trigger Points**
- JSON.parse output fed into merge/extend utilities without key sanitization
- URL query string parsers (`qs`, `querystring`) with nested object notation (`a[__proto__][x]=1`)
- BSON/MessagePack deserialization feeding into recursive merges

## Sink Locations

**Deep Merge / Clone Utilities**
- `_.merge`, `_.mergeWith`, `_.defaultsDeep`, `Object.assign` (shallow — only pollutes if src is controlled)
- `merge-deep`, `deepmerge`, `extend`, `defaults`, `mixin`, `flat.unflatten`

**Path-Set Utilities**
- `lodash.set`, `dot-prop.set`, `object-path.set`

**Template Engines (RCE Gadgets)**
- EJS: `opts.outputFunctionName`, `opts.escapeFunction`, `opts.delimiter`
- Handlebars: `__helperMissing`, `__proto__.main`
- Pug/Jade: `__proto__.compileDebug`, `__proto__.self`
- Nunjucks: `__proto__.toString`

**Child Process Sinks (RCE)**
- Polluted `env`, `shell`, `execPath` options reaching `child_process.spawn` / `exec`

## Vulnerability Patterns

### Recursive Merge Without Key Guard
```javascript
function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object') {
      merge(target[key] ??= {}, source[key]);
    } else {
      target[key] = source[key];  // VULNERABLE: key can be "__proto__"
    }
  }
}
// Exploit: merge({}, JSON.parse('{"__proto__":{"admin":true}}'))
```

### Lodash set / Path Assignment
```javascript
const _ = require('lodash');
_.set(obj, req.body.key, req.body.value);
// Exploit: key = "__proto__.isAdmin", value = "true"
```

### Query String Parser
```javascript
const qs = require('qs');
const params = qs.parse(req.query.raw, { allowPrototypes: false }); // safe
// Vulnerable when allowPrototypes defaults or is explicitly true:
const params = qs.parse(req.query.raw);
```

### EJS RCE via Prototype Pollution
```javascript
// Step 1: pollute Object.prototype.outputFunctionName
Object.prototype.outputFunctionName = 'x;process.mainModule.require("child_process").execSync("id > /tmp/pwn");//';
// Step 2: any res.render() call triggers RCE
res.render('index', {});
```

## Detection Checklist

- [ ] Find all deep merge / clone calls: `_.merge`, `deepmerge`, `Object.assign` receiving user data
- [ ] Check if user-controlled keys are validated against a denylist (`__proto__`, `constructor`, `prototype`)
- [ ] Trace `req.body`, `req.query`, `JSON.parse(req.*)` into any path-set utility
- [ ] Check template engine options objects for pollution gadgets
- [ ] Look for `child_process.spawn` / `exec` where option objects could be tainted
- [ ] Identify npm dependency versions: lodash <4.17.21, merge-deep <3.0.3, hoek <5.0.3

## Sanitization / Mitigations

**Key Guard (sufficient for merge)**
```javascript
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
if (FORBIDDEN.has(key)) continue;
```

**Null-Prototype Object**
```javascript
const safe = Object.create(null);  // no prototype chain to pollute
```

**Frozen Prototype**
```javascript
Object.freeze(Object.prototype);  // prevents all pollution
```

**Use structuredClone (Node 17+)**
```javascript
const clone = structuredClone(userInput);  // sanitizes prototype chains
```

## Severity Escalation

| Impact | Conditions |
|--------|-----------|
| RCE | Template engine with known gadget (EJS, Handlebars, Pug) + render called after pollution |
| Auth Bypass | Polluted `isAdmin`, `role`, `authenticated` read by middleware without `hasOwnProperty` check |
| DoS | Polluted `length` or `toString` causing TypeError in core logic |
| Info Disclosure | Polluted property leaks into serialized API response |

## References
- [portswigger: Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [HackTricks: Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
