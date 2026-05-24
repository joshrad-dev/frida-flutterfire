'use strict';

const REDACT_HEADER_RE = /authorization|token|appcheck|app-check|api-key|key|cookie|secret/i;
const INTERESTING_URL_RE = /firebase|firestore|googleapis|google|gstatic|datadoghq|smartlook|analytics|crashlytics/i;
const INTERESTING_HOST_RE = INTERESTING_URL_RE;
const LOG_ALL_CONNECTS = false;
const ENABLE_NATIVE_NETWORK_TRACE = false;
const LOG_NATIVE_DNS = false;
const LOG_NATIVE_CONNECTS = false;
const LOG_NATIVE_TLS_SNI = true;
const MAX_BODY_PREVIEW = 4096;
const HOST_TRACE_MARKER = '__FIREBASE_TRACE_FILE__ ';
const pendingBlocks = [];
const firestoreMeta = {};
const fieldPathMeta = {};
let traceCounter = 0;

function now() {
  return new Date().toISOString();
}

function log(line) {
  console.log(`[${now()}] ${line}`);
}

function safeString(value) {
  try {
    if (value === null || value === undefined) return String(value);
    if (value.isNull && value.isNull()) return 'NULL';
    const obj = value.handle ? value : new ObjC.Object(value);
    return obj.toString();
  } catch (e) {
    try {
      return value.toString();
    } catch (_) {
      return '<unprintable>';
    }
  }
}

function objcObjectOrNull(value) {
  try {
    if (value === null || value === undefined) return null;
    if (value.handle) return value;
    if (value.isNull && value.isNull()) return null;
    return new ObjC.Object(value);
  } catch (_) {
    return null;
  }
}

function nsString(ptr) {
  if (!ptr || ptr.isNull()) return null;
  try {
    return new ObjC.Object(ptr).toString();
  } catch (_) {
    return null;
  }
}

function redactHeader(name, value) {
  if (REDACT_HEADER_RE.test(name)) return '<redacted>';
  return value;
}

function truncate(text) {
  if (text === null || text === undefined) return String(text);
  const s = String(text);
  return s.length > MAX_BODY_PREVIEW ? `${s.slice(0, MAX_BODY_PREVIEW)}...<truncated ${s.length - MAX_BODY_PREVIEW} chars>` : s;
}

function sanitizeFilePart(text) {
  return String(text || 'trace')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 80) || 'trace';
}

function base64EncodeString(text) {
  const nsText = ObjC.classes.NSString.stringWithString_(String(text));
  const data = nsText.dataUsingEncoding_(4);
  return data.base64EncodedStringWithOptions_(0).toString();
}

function writeTraceText(label, text, extension) {
  const id = String(++traceCounter).padStart(4, '0');
  const fileName = `${id}-${sanitizeFilePart(label)}.${extension || 'txt'}`;
  try {
    console.log(HOST_TRACE_MARKER + JSON.stringify({
      fileName,
      label,
      extension: extension || 'txt',
      encoding: 'base64-utf8',
      content: base64EncodeString(text)
    }));
    return `host:${fileName}`;
  } catch (e) {
    log(`[trace emit error] ${fileName}: ${e}`);
    return `<emit failed ${fileName}>`;
  }
}

function writeTraceData(label, dataObj) {
  try {
    if (!dataObj || dataObj.isNull()) return 'nil';
    const data = dataObj.handle ? dataObj : new ObjC.Object(dataObj);
    const id = String(++traceCounter).padStart(4, '0');
    const fileName = `${id}-${sanitizeFilePart(label)}.bin`;
    console.log(HOST_TRACE_MARKER + JSON.stringify({
      fileName,
      label,
      extension: 'bin',
      encoding: 'base64',
      content: data.base64EncodedStringWithOptions_(0).toString()
    }));
    return `host:${fileName}`;
  } catch (e) {
    log(`[trace data emit error] ${e}`);
    return '<emit failed>';
  }
}

function writeTraceJSON(label, value) {
  return writeTraceText(label, JSON.stringify(value, null, 2), 'json');
}

function logTraceRecord(label, record) {
  const file = writeTraceJSON(label, Object.assign({ capturedAt: now() }, record));
  const method = record.method || label;
  const path = record.path || record.request?.path || record.request?.url || '';
  log(`[trace ${method}] ${path} full=${file}`);
  return file;
}

function logPendingTrace(method, path) {
  log(`[pending ${method}] ${path || ''}`);
}

function persistText(label, text, extension) {
  const full = String(text);
  const path = writeTraceText(label, full, extension || 'txt');
  return `${truncate(full)} full=${path}`;
}

function dataPreview(dataObj) {
  try {
    if (!dataObj || dataObj.isNull()) return 'nil';
    const data = dataObj.handle ? dataObj : new ObjC.Object(dataObj);
    const len = Number(data.length());
    if (len === 0) return '0 bytes';

    const nsString = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
    if (nsString && !nsString.isNull()) {
      const full = nsString.toString();
      const path = writeTraceText('http-body', full, 'txt');
      return `${len} bytes utf8=${truncate(full)} full=${path}`;
    }

    const filePath = writeTraceData('http-body', data);
    const bytes = data.bytes();
    const count = Math.min(len, 128);
    const hex = [];
    for (let i = 0; i < count; i++) {
      const b = readU8(bytes.add(i));
      hex.push(b.toString(16).padStart(2, '0'));
    }
    return `${len} bytes hex=${hex.join(' ')}${len > count ? ' ...' : ''} full=${filePath}`;
  } catch (e) {
    return `<data unreadable ${e}>`;
  }
}

function objcToPlain(value, depth) {
  if (value === null || value === undefined) return null;
  if (depth > 5) return '<max-depth>';

  let obj;
  try {
    if (value.isNull && value.isNull()) return null;
    obj = value.handle ? value : new ObjC.Object(value);
  } catch (_) {
    return safeString(value);
  }

  try {
    const firebasePlain = firebaseObjectToPlain(obj, depth);
    if (firebasePlain !== undefined) return firebasePlain;

    if (obj.isKindOfClass_(ObjC.classes.NSString)) return obj.toString();
    if (obj.isKindOfClass_(ObjC.classes.NSNumber)) return obj.toString();
    if (ObjC.classes.NSDate && obj.isKindOfClass_(ObjC.classes.NSDate)) return obj.toString();
    if (ObjC.classes.NSNull && obj.isKindOfClass_(ObjC.classes.NSNull)) return null;

    if (obj.isKindOfClass_(ObjC.classes.NSData)) {
      return dataPreview(obj);
    }

    if (obj.isKindOfClass_(ObjC.classes.NSArray)) {
      const arr = [];
      const count = Number(obj.count());
      for (let i = 0; i < Math.min(count, 50); i++) {
        arr.push(objcToPlain(obj.objectAtIndex_(i), depth + 1));
      }
      if (count > 50) arr.push(`<${count - 50} more items>`);
      return arr;
    }

    if (obj.isKindOfClass_(ObjC.classes.NSDictionary)) {
      const out = {};
      const keys = obj.allKeys();
      const count = Number(keys.count());
      for (let i = 0; i < Math.min(count, 80); i++) {
        const keyObj = keys.objectAtIndex_(i);
        const key = keyObj.toString();
        out[key] = objcToPlain(obj.objectForKey_(keyObj), depth + 1);
      }
      if (count > 80) out['<truncated>'] = `${count - 80} more keys`;
      return out;
    }
  } catch (_) {}

  return safeString(obj);
}

function trySelectorString(obj, selectorName) {
  try {
    if (obj.respondsToSelector_(selectorName)) {
      const value = obj[selectorName]();
      if (value === null || value === undefined) return null;
      if (value.isNull && value.isNull()) return null;
      return safeString(value);
    }
  } catch (_) {}
  return null;
}

function firebaseObjectToPlain(obj, depth) {
  try {
    const className = obj.$className || '';

    if (className === 'FIRDocumentReference') {
      return {
        __type: 'FIRDocumentReference',
        path: trySelectorString(obj, 'path'),
        documentID: trySelectorString(obj, 'documentID'),
        parentPath: (() => {
          try {
            const parent = obj.parent();
            return parent && !parent.isNull() ? safeString(parent.path()) : null;
          } catch (_) {
            return null;
          }
        })()
      };
    }

    if (className === 'FIRCollectionReference') {
      return {
        __type: 'FIRCollectionReference',
        path: trySelectorString(obj, 'path'),
        collectionID: trySelectorString(obj, 'collectionID'),
        parentPath: (() => {
          try {
            const parent = obj.parent();
            return parent && !parent.isNull() ? safeString(parent.path()) : null;
          } catch (_) {
            return null;
          }
        })()
      };
    }

    if (className === 'FIRFieldPath') {
      return {
        __type: 'FIRFieldPath',
        path: fieldPathToReadable(obj)
      };
    }

    if (className === 'FIRGeoPoint') {
      return {
        __type: 'FIRGeoPoint',
        latitude: Number(obj.latitude()),
        longitude: Number(obj.longitude())
      };
    }

    if (className === 'FIRTimestamp') {
      return {
        __type: 'FIRTimestamp',
        seconds: Number(obj.seconds()),
        nanoseconds: Number(obj.nanoseconds()),
        iso8601: trySelectorString(obj, 'ISO8601String')
      };
    }

    if (className === 'FIRFieldValue') {
      return {
        __type: 'FIRFieldValue',
        description: safeString(obj)
      };
    }
  } catch (_) {}

  return undefined;
}

function fieldPathToReadable(value) {
  try {
    if (!value || value.isNull()) return null;
    const obj = value.handle ? value : new ObjC.Object(value);
    const remembered = getRememberedFieldPath(obj.handle || obj);
    if (remembered) return remembered;

    const desc = safeString(obj);
    if (desc && !/^<FIRFieldPath: /.test(desc)) return desc;

    try {
      const ivars = obj.$ivars;
      const candidates = [];
      Object.keys(ivars || {}).forEach((name) => {
        try {
          if (name === 'isa') return;
          const rendered = foundationOrSummary(ivars[name], 0);
          candidates.push({ name, value: rendered });
        } catch (_) {}
      });
      if (candidates.length > 0) return { description: desc, ivars: candidates };
    } catch (_) {}

    return desc;
  } catch (_) {
    return safeString(value);
  }
}

function fieldArgToPlain(value) {
  const plain = objcToPlain(value, 0);
  if (plain && typeof plain === 'object' && plain.__type === 'FIRFieldPath') return plain.path;
  return plain;
}

function jsonish(value) {
  try {
    return persistText('objc-json', JSON.stringify(objcToPlain(value, 0), null, 2), 'json');
  } catch (_) {
    return persistText('objc-text', safeString(value), 'txt');
  }
}

function objectKey(value) {
  try {
    if (!value || value.isNull()) return null;
    return value.toString();
  } catch (_) {
    return null;
  }
}

function rememberFieldPath(value, readable) {
  const key = objectKey(value);
  if (!key) return;
  fieldPathMeta[key] = readable;
}

function getRememberedFieldPath(value) {
  const key = objectKey(value);
  return key && fieldPathMeta[key] ? fieldPathMeta[key] : null;
}

function clonePlain(value) {
  try {
    return JSON.parse(JSON.stringify(value || {}));
  } catch (_) {
    return {};
  }
}

function foundationOrSummary(value, depth) {
  if (value === null || value === undefined) return null;
  if (depth > 2) return safeString(value);

  let obj;
  try {
    if (value.isNull && value.isNull()) return null;
    obj = value.handle ? value : new ObjC.Object(value);
  } catch (_) {
    return safeString(value);
  }

  try {
    const firebasePlain = firebaseObjectToPlain(obj, depth);
    if (firebasePlain !== undefined) return firebasePlain;

    if (obj.isKindOfClass_(ObjC.classes.NSString)) return obj.toString();
    if (obj.isKindOfClass_(ObjC.classes.NSNumber)) return obj.toString();
    if (ObjC.classes.NSDate && obj.isKindOfClass_(ObjC.classes.NSDate)) return obj.toString();
    if (ObjC.classes.NSNull && obj.isKindOfClass_(ObjC.classes.NSNull)) return null;
    if (obj.isKindOfClass_(ObjC.classes.NSArray)) {
      const out = [];
      const count = Number(obj.count());
      for (let i = 0; i < Math.min(count, 20); i++) {
        out.push(foundationOrSummary(obj.objectAtIndex_(i), depth + 1));
      }
      if (count > 20) out.push(`<${count - 20} more items>`);
      return out;
    }
    if (obj.isKindOfClass_(ObjC.classes.NSDictionary)) {
      const out = {};
      const keys = obj.allKeys();
      const count = Number(keys.count());
      for (let i = 0; i < Math.min(count, 30); i++) {
        const keyObj = keys.objectAtIndex_(i);
        out[keyObj.toString()] = foundationOrSummary(obj.objectForKey_(keyObj), depth + 1);
      }
      if (count > 30) out['<truncated>'] = `${count - 30} more keys`;
      return out;
    }
  } catch (_) {}

  return {
    className: obj.$className || '<unknown>',
    description: safeString(obj)
  };
}

function objectDiagnostics(value) {
  const out = {};
  try {
    if (!value || value.isNull()) return out;
    const obj = value.handle ? value : new ObjC.Object(value);
    out.className = obj.$className || '<unknown>';
    out.description = safeString(obj);

    try {
      const ivars = obj.$ivars;
      const ivarOut = {};
      Object.keys(ivars || {}).forEach((name) => {
        try {
          ivarOut[name] = foundationOrSummary(ivars[name], 0);
        } catch (e) {
          ivarOut[name] = `<unreadable ${e}>`;
        }
      });
      if (Object.keys(ivarOut).length > 0) out.ivars = ivarOut;
    } catch (_) {}

    const firebasePlain = firebaseObjectToPlain(obj, 0);
    if (firebasePlain !== undefined) out.readable = firebasePlain;

    ['path', 'documentID', 'collectionID'].forEach((selectorName) => {
      try {
        const selector = `${selectorName}`;
        if (obj.respondsToSelector_(selector)) {
          out[selectorName] = safeString(obj[`${selectorName}`]());
        }
      } catch (_) {}
    });
  } catch (e) {
    out.error = String(e);
  }
  return out;
}

function rememberFirestoreMeta(value, meta) {
  const key = objectKey(value);
  if (!key) return;
  firestoreMeta[key] = Object.assign(clonePlain(meta), {
    object: objectDiagnostics(value)
  });
}

function getFirestoreMeta(value) {
  const key = objectKey(value);
  if (key && firestoreMeta[key]) {
    const meta = clonePlain(firestoreMeta[key]);
    if (!meta.object) meta.object = objectDiagnostics(value);
    return meta;
  }
  return {
    type: 'unknown',
    path: null,
    filters: [],
    orderBy: [],
    limit: null,
    object: objectDiagnostics(value)
  };
}

function appendPath(base, child) {
  if (!base) return child || null;
  if (!child) return base;
  return `${base}/${child}`;
}

function queryMetaWith(meta, change) {
  const next = clonePlain(meta);
  next.filters = next.filters || [];
  next.orderBy = next.orderBy || [];
  Object.keys(change).forEach((key) => {
    if (key === 'filters') next.filters = next.filters.concat(change.filters);
    else if (key === 'orderBy') next.orderBy = next.orderBy.concat(change.orderBy);
    else next[key] = change[key];
  });
  return next;
}

function errorPlain(error) {
  return error && !error.isNull() ? safeString(error) : null;
}

function documentSnapshotPlain(snapshotPtr) {
  if (!snapshotPtr || snapshotPtr.isNull()) return null;
  const snapshot = new ObjC.Object(snapshotPtr);
  const out = {};
  try {
    out.documentID = snapshot.documentID().toString();
  } catch (_) {}
  try {
    out.data = objcToPlain(snapshot.data(), 0);
  } catch (e) {
    out.dataError = String(e);
  }
  try {
    const ref = snapshot.reference();
    out.path = getFirestoreMeta(ref.handle || ref).path;
  } catch (_) {}
  return out;
}

function querySnapshotPlain(snapshotPtr) {
  if (!snapshotPtr || snapshotPtr.isNull()) return null;
  const snapshot = new ObjC.Object(snapshotPtr);
  const docs = snapshot.documents();
  const count = Number(docs.count());
  const out = [];
  for (let i = 0; i < count; i++) {
    const doc = docs.objectAtIndex_(i);
    out.push(documentSnapshotPlain(doc.handle || doc));
  }
  return { count, documents: out };
}

function describeDocumentSnapshot(snapshotPtr) {
  try {
    if (!snapshotPtr || snapshotPtr.isNull()) return 'snapshot=nil';
    const snapshot = new ObjC.Object(snapshotPtr);
    const pieces = [];
    try {
      pieces.push(`documentID=${snapshot.documentID().toString()}`);
    } catch (_) {}
    try {
      pieces.push(`data=${jsonish(snapshot.data())}`);
    } catch (e) {
      pieces.push(`data=<unreadable ${e}>`);
    }
    return pieces.join(' ');
  } catch (e) {
    return `<document snapshot unreadable ${e}>`;
  }
}

function describeQuerySnapshot(snapshotPtr) {
  try {
    if (!snapshotPtr || snapshotPtr.isNull()) return 'snapshot=nil';
    const snapshot = new ObjC.Object(snapshotPtr);
    const docs = snapshot.documents();
    const count = Number(docs.count());
    const rendered = [];
    for (let i = 0; i < count; i++) {
      rendered.push(objcToPlain(docs.objectAtIndex_(i).data(), 0));
    }
    const full = JSON.stringify(rendered, null, 2);
    const path = writeTraceText('firestore-query-snapshot', full, 'json');
    return `count=${count} docs=${truncate(full)} full=${path}`;
  } catch (e) {
    return `<query snapshot unreadable ${e}>`;
  }
}

function firestoreCompletionRenderer(kind) {
  return function (snapshot, error) {
    const err = error && !error.isNull() ? safeString(error) : 'nil';
    if (kind === 'query') return `${describeQuerySnapshot(snapshot)} error=${err}`;
    return `${describeDocumentSnapshot(snapshot)} error=${err}`;
  };
}

function responseSummary(responsePtr) {
  try {
    const response = objcObjectOrNull(responsePtr);
    if (!response) return `response=${safeString(responsePtr)}`;
    const pieces = [];
    if (response.respondsToSelector_('statusCode')) pieces.push(`status=${response.statusCode()}`);
    const url = response.URL && response.URL();
    if (url && !url.isNull()) pieces.push(`url=${url.absoluteString().toString()}`);
    return pieces.length > 0 ? pieces.join(' ') : response.toString();
  } catch (e) {
    return `<response unreadable ${e}>`;
  }
}

function wrapCompletionBlock(blockPtr, label, renderer) {
  if (!blockPtr || blockPtr.isNull()) return;

  try {
    const block = new ObjC.Block(blockPtr);
    const original = block.implementation;
    block.implementation = function () {
      try {
        log(`[${label}] ${renderer.apply(null, arguments)}`);
      } catch (e) {
        log(`[${label}] <renderer error ${e}>`);
      }
      return original.apply(this, arguments);
    };
    pendingBlocks.push(block);
  } catch (e) {
    log(`[block wrap failed] ${label}: ${e}`);
  }
}

function describeURLRequest(reqObj) {
  const pieces = [];

  try {
    const method = reqObj.HTTPMethod();
    if (method && !method.isNull()) pieces.push(method.toString());
  } catch (_) {}

  try {
    const url = reqObj.URL();
    if (url && !url.isNull()) pieces.push(url.absoluteString().toString());
  } catch (_) {}

  try {
    const headers = reqObj.allHTTPHeaderFields();
    if (headers && !headers.isNull()) {
      const dict = new ObjC.Object(headers);
      const keys = dict.allKeys();
      const count = keys.count();
      const rendered = [];

      for (let i = 0; i < count; i++) {
        const key = keys.objectAtIndex_(i).toString();
        const value = dict.objectForKey_(key).toString();
        rendered.push(`${key}=${redactHeader(key, value)}`);
      }

      if (rendered.length > 0) pieces.push(`headers{${rendered.join(', ')}}`);
    }
  } catch (_) {}

  try {
    const body = reqObj.HTTPBody();
    if (body && !body.isNull()) pieces.push(`body=${dataPreview(body)}`);
  } catch (_) {}

  return pieces.join(' ');
}

function requestURLString(reqPtr) {
  try {
    if (!reqPtr || reqPtr.isNull()) return null;
    const req = new ObjC.Object(reqPtr);
    if (req.respondsToSelector_('absoluteString')) {
      return req.absoluteString().toString();
    }
    const url = req.URL();
    if (!url || url.isNull()) return null;
    return url.absoluteString().toString();
  } catch (_) {
    return null;
  }
}

function shouldLogURL(url) {
  return !url || INTERESTING_URL_RE.test(url);
}

function attachMethod(className, selector, callbacks) {
  if (!ObjC.available) return false;

  const klass = ObjC.classes[className];
  if (!klass || !klass[selector]) {
    return false;
  }

  try {
    Interceptor.attach(klass[selector].implementation, callbacks);
    log(`[hooked] ${className} ${selector}`);
    return true;
  } catch (e) {
    log(`[hook failed] ${className} ${selector}: ${e}`);
    return false;
  }
}

function ntohs(n) {
  return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

function readU8(addr) {
  return typeof Memory.readU8 === 'function' ? Memory.readU8(addr) : addr.readU8();
}

function readU16(addr) {
  return typeof Memory.readU16 === 'function' ? Memory.readU16(addr) : addr.readU16();
}

function readPointer(addr) {
  return typeof Memory.readPointer === 'function' ? Memory.readPointer(addr) : addr.readPointer();
}

function readUtf8String(addr) {
  return typeof Memory.readUtf8String === 'function' ? Memory.readUtf8String(addr) : addr.readUtf8String();
}

function readSockaddr(addr) {
  if (!addr || addr.isNull()) return null;

  const family = readU8(addr.add(1));

  if (family === 2) {
    const port = ntohs(readU16(addr.add(2)));
    const host = [
      readU8(addr.add(4)),
      readU8(addr.add(5)),
      readU8(addr.add(6)),
      readU8(addr.add(7))
    ].join('.');

    return { family: 'IPv4', host, port, address: `${host}:${port}` };
  }

  if (family === 30) {
    const port = ntohs(readU16(addr.add(2)));
    const parts = [];

    for (let i = 0; i < 8; i++) {
      parts.push(ntohs(readU16(addr.add(8 + i * 2))).toString(16));
    }

    const host = parts.join(':');
    return { family: 'IPv6', host, port, address: `[${host}]:${port}` };
  }

  if (family === 1) {
    return { family: 'Unix', host: null, port: null, address: 'AF_UNIX' };
  }

  return { family: `unknown(${family})`, host: null, port: null, address: `family=${family}` };
}

function attachExport(moduleName, exportName, callbacks) {
  let ptr = null;

  if (typeof Module.findExportByName === 'function') {
    ptr = Module.findExportByName(moduleName, exportName);
  } else if (moduleName === null && typeof Module.findGlobalExportByName === 'function') {
    ptr = Module.findGlobalExportByName(exportName);
  } else if (moduleName && typeof Process.findModuleByName === 'function') {
    const module = Process.findModuleByName(moduleName);
    if (module && typeof module.findExportByName === 'function') {
      ptr = module.findExportByName(exportName);
    } else if (module && typeof module.getExportByName === 'function') {
      try {
        ptr = module.getExportByName(exportName);
      } catch (_) {}
    }
  }

  if (!ptr) return false;

  try {
    Interceptor.attach(ptr, callbacks);
    log(`[hooked] ${exportName}`);
    return true;
  } catch (e) {
    log(`[hook failed] ${exportName}: ${e}`);
    return false;
  }
}

function shouldLogHost(host) {
  return LOG_ALL_CONNECTS || !host || INTERESTING_HOST_RE.test(host);
}

function hookNativeDartNetwork() {
  attachExport(null, 'getaddrinfo', {
    onEnter(args) {
      this.node = args[0].isNull() ? null : readUtf8String(args[0]);
      this.service = args[1].isNull() ? null : readUtf8String(args[1]);
    },
    onLeave(retval) {
      if (LOG_NATIVE_DNS && this.node && shouldLogHost(this.node)) {
        log(`[native getaddrinfo] ${this.node}${this.service ? ':' + this.service : ''} => ${retval.toInt32()}`);
      }
    }
  });

  attachExport(null, 'connect', {
    onEnter(args) {
      const dest = readSockaddr(args[1]);
      if (!dest) return;

      if (LOG_NATIVE_CONNECTS && (LOG_ALL_CONNECTS || dest.port === 443 || dest.port === 80 || dest.port === 8888)) {
        log(`[native connect] ${dest.address}`);
      }
    }
  });

  attachExport(null, 'connectx', {
    onEnter(args) {
      const endpoints = args[1];
      if (endpoints.isNull()) return;

      const dstaddrOffset = 24;
      const sockaddrPtr = readPointer(endpoints.add(dstaddrOffset));
      const dest = readSockaddr(sockaddrPtr);
      if (!dest) return;

      if (LOG_NATIVE_CONNECTS && (LOG_ALL_CONNECTS || dest.port === 443 || dest.port === 80 || dest.port === 8888)) {
        log(`[native connectx] ${dest.address}`);
      }
    }
  });

  attachExport(null, 'SSL_set_tlsext_host_name', {
    onEnter(args) {
      const hostname = args[1].isNull() ? null : readUtf8String(args[1]);
      if (LOG_NATIVE_TLS_SNI && hostname && shouldLogHost(hostname)) {
        log(`[native TLS SNI] ${hostname}`);
      }
    }
  });
}

function hookURLSessionSelector(selector) {
  attachMethod('NSURLSession', selector, {
    onEnter(args) {
      const url = requestURLString(args[2]);
      if (!shouldLogURL(url)) return;

      try {
        const req = new ObjC.Object(args[2]);
        log(`[NSURLSession ${selector}] ${describeURLRequest(req)}`);
      } catch (e) {
        log(`[NSURLSession ${selector}] ${url || '<request unreadable>'}`);
      }

      if (selector === '- dataTaskWithRequest:completionHandler:' ||
          selector === '- dataTaskWithURL:completionHandler:' ||
          selector === '- downloadTaskWithRequest:completionHandler:' ||
          selector === '- downloadTaskWithURL:completionHandler:') {
        wrapCompletionBlock(args[3], `NSURLSession completion ${url || selector}`, function (data, response, error) {
          return `${responseSummary(response)} error=${error && !error.isNull() ? safeString(error) : 'nil'} data=${dataPreview(data)}`;
        });
      }

      if (selector === '- uploadTaskWithRequest:fromData:completionHandler:') {
        log(`[NSURLSession upload payload] ${dataPreview(args[3])}`);
        wrapCompletionBlock(args[4], `NSURLSession upload completion ${url || selector}`, function (data, response, error) {
          return `${responseSummary(response)} error=${error && !error.isNull() ? safeString(error) : 'nil'} data=${dataPreview(data)}`;
        });
      }

      if (selector === '- uploadTaskWithRequest:fromFile:completionHandler:') {
        log(`[NSURLSession upload file] ${safeString(args[3])}`);
        wrapCompletionBlock(args[4], `NSURLSession upload completion ${url || selector}`, function (data, response, error) {
          return `${responseSummary(response)} error=${error && !error.isNull() ? safeString(error) : 'nil'} data=${dataPreview(data)}`;
        });
      }
    }
  });
}

function hookGTMSessionFetcher() {
  attachMethod('GTMSessionFetcher', '- initWithRequest:', {
    onEnter(args) {
      const url = requestURLString(args[2]);
      if (!shouldLogURL(url)) return;

      this.shouldLog = true;
      try {
        log(`[GTM initWithRequest] ${describeURLRequest(new ObjC.Object(args[2]))}`);
      } catch (_) {
        log(`[GTM initWithRequest] ${url}`);
      }
    }
  });

  attachMethod('GTMSessionFetcher', '- setRequest:', {
    onEnter(args) {
      const url = requestURLString(args[2]);
      if (!shouldLogURL(url)) return;

      try {
        log(`[GTM setRequest] ${describeURLRequest(new ObjC.Object(args[2]))}`);
      } catch (_) {
        log(`[GTM setRequest] ${url}`);
      }
    }
  });

  attachMethod('GTMSessionFetcher', '- beginFetchWithCompletionHandler:', {
    onEnter(args) {
      try {
        const fetcher = new ObjC.Object(args[0]);
        const req = fetcher.request();
        const url = req && !req.isNull() ? req.URL().absoluteString().toString() : null;
        if (shouldLogURL(url)) {
          log(`[GTM beginFetch] ${describeURLRequest(req)}`);
        }
      } catch (e) {
        log(`[GTM beginFetch] <unreadable> ${e}`);
      }
    }
  });

  attachMethod('GTMSessionFetcher', '- URLSession:task:didCompleteWithError:', {
    onEnter(args) {
      try {
        const task = new ObjC.Object(args[3]);
        const req = task.currentRequest();
        const url = req && !req.isNull() ? req.URL().absoluteString().toString() : null;
        if (!shouldLogURL(url)) return;

        const error = args[4].isNull() ? 'nil' : new ObjC.Object(args[4]).toString();
        const response = task.response();
        const status = response && !response.isNull() && response.respondsToSelector_('statusCode')
          ? response.statusCode()
          : 'n/a';
        log(`[GTM complete] status=${status} error=${error} ${url || ''}`);
      } catch (e) {
        log(`[GTM complete] <unreadable> ${e}`);
      }
    }
  });

  attachMethod('GTMSessionFetcher', '- URLSession:dataTask:didReceiveData:', {
    onEnter(args) {
      try {
        const task = new ObjC.Object(args[3]);
        const req = task.currentRequest();
        const url = req && !req.isNull() ? req.URL().absoluteString().toString() : null;
        if (!shouldLogURL(url)) return;
        log(`[GTM receiveData] ${url || ''} data=${dataPreview(args[4])}`);
      } catch (e) {
        log(`[GTM receiveData] <unreadable> ${e}`);
      }
    }
  });
}

function hookFirebaseHighLevel() {
  attachMethod('FIRFieldPath', '+ pathWithDotSeparatedString:', {
    onEnter(args) {
      this.path = nsString(args[2]);
    },
    onLeave(retval) {
      rememberFieldPath(retval, this.path);
      log(`[FIRFieldPath pathWithDotSeparatedString] ${this.path}`);
    }
  });

  attachMethod('FIRFieldPath', '+ documentID', {
    onLeave(retval) {
      rememberFieldPath(retval, '__name__');
      log('[FIRFieldPath documentID] __name__');
    }
  });

  attachMethod('FIRFieldPath', '- initWithFields:', {
    onEnter(args) {
      this.self = args[0];
      this.fields = objcToPlain(args[2], 0);
    },
    onLeave(retval) {
      const readable = Array.isArray(this.fields) ? this.fields.join('.') : this.fields;
      rememberFieldPath(retval, readable);
      rememberFieldPath(this.self, readable);
      log(`[FIRFieldPath initWithFields] ${JSON.stringify(this.fields)}`);
    }
  });

  attachMethod('FIRHTTPSCallable', '- callWithObject:completion:', {
    onEnter(args) {
      log(`[FIRHTTPSCallable callWithObject] data=${safeString(args[2])}`);
    }
  });

  attachMethod('FIRHTTPSCallable', '- callWithCompletion:', {
    onEnter() {
      log('[FIRHTTPSCallable callWithCompletion]');
    }
  });

  attachMethod('FIRFunctions', '- HTTPSCallableWithName:', {
    onEnter(args) {
      log(`[FIRFunctions HTTPSCallableWithName] ${nsString(args[2])}`);
    }
  });

  attachMethod('FIRFunctions', '- HTTPSCallableWithName:options:', {
    onEnter(args) {
      log(`[FIRFunctions HTTPSCallableWithName:options] ${nsString(args[2])}`);
    }
  });

  attachMethod('FIRFunctions', '- HTTPSCallableWithURL:', {
    onEnter(args) {
      log(`[FIRFunctions HTTPSCallableWithURL] ${safeString(args[2])}`);
    }
  });

  attachMethod('FIRAppCheck', '- tokenForcingRefresh:completion:', {
    onEnter(args) {
      log(`[FIRAppCheck tokenForcingRefresh] forcing=${args[2].toInt32()}`);
    }
  });

  attachMethod('FIRAppCheck', '- getTokenForcingRefresh:completion:', {
    onEnter(args) {
      log(`[FIRAppCheck getTokenForcingRefresh] forcing=${args[2].toInt32()}`);
    }
  });

  attachMethod('FIRInstallations', '- authTokenWithCompletion:', {
    onEnter() {
      log('[FIRInstallations authTokenWithCompletion]');
    }
  });

  attachMethod('FIRInstallations', '- authTokenForcingRefresh:completion:', {
    onEnter(args) {
      log(`[FIRInstallations authTokenForcingRefresh] forcing=${args[2].toInt32()}`);
    }
  });

  attachMethod('FIRAuth', '- getTokenForcingRefresh:withCallback:', {
    onEnter(args) {
      log(`[FIRAuth getTokenForcingRefresh] forcing=${args[2].toInt32()}`);
    }
  });

  attachMethod('FIRAuth', '- signInWithCredential:completion:', {
    onEnter(args) {
      log(`[FIRAuth signInWithCredential] credential=${safeString(args[2])}`);
    }
  });

  attachMethod('FIRAuth', '- signInAnonymouslyWithCompletion:', {
    onEnter() {
      log('[FIRAuth signInAnonymouslyWithCompletion]');
    }
  });

  attachMethod('FIRAuth', '- signInWithCustomToken:completion:', {
    onEnter(args) {
      log(`[FIRAuth signInWithCustomToken] token=<redacted> len=${nsString(args[2])?.length || 0}`);
    }
  });

  attachMethod('FIRFirestore', '- collectionWithPath:', {
    onEnter(args) {
      this.path = nsString(args[2]);
      log(`[FIRFirestore collectionWithPath] ${this.path}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, {
        type: 'collection',
        path: this.path,
        filters: [],
        orderBy: [],
        limit: null
      });
    }
  });

  attachMethod('FIRFirestore', '- documentWithPath:', {
    onEnter(args) {
      this.path = nsString(args[2]);
      log(`[FIRFirestore documentWithPath] ${this.path}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, {
        type: 'document',
        path: this.path
      });
    }
  });

  attachMethod('FIRFirestore', '- collectionGroupWithID:', {
    onEnter(args) {
      this.collectionID = nsString(args[2]);
      log(`[FIRFirestore collectionGroupWithID] ${this.collectionID}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, {
        type: 'collectionGroup',
        path: `**/${this.collectionID}`,
        collectionID: this.collectionID,
        filters: [],
        orderBy: [],
        limit: null
      });
    }
  });

  attachMethod('FIRDocumentReference', '- setData:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.setData',
        path: meta.path,
        request: {
          type: 'write',
          operation: 'setData',
          reference: meta,
          data: objcToPlain(args[2], 0)
        }
      };
      logPendingTrace(record.method, record.path);
    }
  });

  attachMethod('FIRDocumentReference', '- collectionWithPath:', {
    onEnter(args) {
      this.parentMeta = getFirestoreMeta(args[0]);
      this.childPath = nsString(args[2]);
      log(`[FIRDocumentReference collectionWithPath] ${appendPath(this.parentMeta.path, this.childPath)}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, {
        type: 'collection',
        path: appendPath(this.parentMeta.path, this.childPath),
        parent: this.parentMeta,
        filters: [],
        orderBy: [],
        limit: null
      });
    }
  });

  attachMethod('FIRDocumentReference', '- setData:completion:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.setData:completion',
        path: meta.path,
        request: {
          type: 'write',
          operation: 'setData',
          reference: meta,
          data: objcToPlain(args[2], 0)
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRDocumentReference setData completion', function (error) {
        record.response = { error: errorPlain(error) };
        const file = logTraceRecord('firestore-setData-response', record);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRDocumentReference', '- setData:merge:completion:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.setData:merge:completion',
        path: meta.path,
        request: {
          type: 'write',
          operation: 'setData',
          merge: !!args[3].toInt32(),
          reference: meta,
          data: objcToPlain(args[2], 0)
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[4], 'FIRDocumentReference setData merge completion', function (error) {
        record.response = { error: errorPlain(error) };
        const file = logTraceRecord('firestore-setData-merge-response', record);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRDocumentReference', '- updateData:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.updateData',
        path: meta.path,
        request: {
          type: 'write',
          operation: 'updateData',
          reference: meta,
          data: objcToPlain(args[2], 0)
        }
      };
      logPendingTrace(record.method, record.path);
    }
  });

  attachMethod('FIRDocumentReference', '- updateData:completion:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.updateData:completion',
        path: meta.path,
        request: {
          type: 'write',
          operation: 'updateData',
          reference: meta,
          data: objcToPlain(args[2], 0)
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRDocumentReference updateData completion', function (error) {
        record.response = { error: errorPlain(error) };
        const file = logTraceRecord('firestore-updateData-response', record);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRCollectionReference', '- addDocumentWithData:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRCollectionReference.addDocumentWithData',
        path: meta.path,
        request: {
          type: 'write',
          operation: 'addDocument',
          collection: meta,
          data: objcToPlain(args[2], 0)
        }
      };
      logPendingTrace(record.method, record.path);
    }
  });

  attachMethod('FIRCollectionReference', '- addDocumentWithData:completion:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRCollectionReference.addDocumentWithData:completion',
        path: meta.path,
        request: {
          type: 'write',
          operation: 'addDocument',
          collection: meta,
          data: objcToPlain(args[2], 0)
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRCollectionReference addDocument completion', function (error) {
        record.response = { error: errorPlain(error) };
        const file = logTraceRecord('firestore-addDocument-response', record);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRCollectionReference', '- documentWithPath:', {
    onEnter(args) {
      this.parentMeta = getFirestoreMeta(args[0]);
      this.childPath = nsString(args[2]);
      log(`[FIRCollectionReference documentWithPath] ${appendPath(this.parentMeta.path, this.childPath)}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, {
        type: 'document',
        path: appendPath(this.parentMeta.path, this.childPath),
        parent: this.parentMeta
      });
    }
  });

  attachMethod('FIRDocumentReference', '- getDocumentWithCompletion:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.getDocumentWithCompletion',
        path: meta.path,
        request: {
          type: 'read',
          operation: 'getDocument',
          reference: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[2], 'FIRDocumentReference getDocument record', function (snapshot, error) {
        record.response = {
          error: errorPlain(error),
          document: documentSnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-getDocument-response', record);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRDocumentReference', '- getDocumentWithSource:completion:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const source = args[2].toInt32();
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.getDocumentWithSource:completion',
        path: meta.path,
        request: {
          type: 'read',
          operation: 'getDocument',
          source,
          reference: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRDocumentReference getDocument source record', function (snapshot, error) {
        record.response = {
          error: errorPlain(error),
          document: documentSnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-getDocument-source-response', record);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRDocumentReference', '- addSnapshotListener:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.addSnapshotListener',
        path: meta.path,
        request: {
          type: 'listen',
          operation: 'documentSnapshotListener',
          reference: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[2], 'FIRDocumentReference snapshot listener record', function (snapshot, error) {
        const eventRecord = clonePlain(record);
        eventRecord.response = {
          error: errorPlain(error),
          document: documentSnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-document-listener-event', eventRecord);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRDocumentReference', '- addSnapshotListenerWithIncludeMetadataChanges:listener:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const includeMetadataChanges = !!args[2].toInt32();
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.addSnapshotListenerWithIncludeMetadataChanges:listener',
        path: meta.path,
        request: {
          type: 'listen',
          operation: 'documentSnapshotListener',
          includeMetadataChanges,
          reference: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRDocumentReference snapshot listener record', function (snapshot, error) {
        const eventRecord = clonePlain(record);
        eventRecord.response = {
          error: errorPlain(error),
          document: documentSnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-document-listener-event', eventRecord);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRDocumentReference', '- addSnapshotListenerWithOptions:listener:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRDocumentReference.addSnapshotListenerWithOptions:listener',
        path: meta.path,
        request: {
          type: 'listen',
          operation: 'documentSnapshotListener',
          options: safeString(args[2]),
          reference: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRDocumentReference snapshot listener record', function (snapshot, error) {
        const eventRecord = clonePlain(record);
        eventRecord.response = {
          error: errorPlain(error),
          document: documentSnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-document-listener-event', eventRecord);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRQuery', '- getDocumentsWithCompletion:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRQuery.getDocumentsWithCompletion',
        path: meta.path,
        request: {
          type: 'read',
          operation: 'getDocuments',
          query: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[2], 'FIRQuery getDocuments record', function (snapshot, error) {
        record.response = {
          error: errorPlain(error),
          querySnapshot: querySnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-getDocuments-response', record);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRQuery', '- getDocumentsWithSource:completion:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const source = args[2].toInt32();
      const record = {
        kind: 'firestore',
        method: 'FIRQuery.getDocumentsWithSource:completion',
        path: meta.path,
        request: {
          type: 'read',
          operation: 'getDocuments',
          source,
          query: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRQuery getDocuments source record', function (snapshot, error) {
        record.response = {
          error: errorPlain(error),
          querySnapshot: querySnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-getDocuments-source-response', record);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRQuery', '- addSnapshotListener:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRQuery.addSnapshotListener',
        path: meta.path,
        request: {
          type: 'listen',
          operation: 'querySnapshotListener',
          query: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[2], 'FIRQuery snapshot listener record', function (snapshot, error) {
        const eventRecord = clonePlain(record);
        eventRecord.response = {
          error: errorPlain(error),
          querySnapshot: querySnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-query-listener-event', eventRecord);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRQuery', '- addSnapshotListenerWithIncludeMetadataChanges:listener:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const includeMetadataChanges = !!args[2].toInt32();
      const record = {
        kind: 'firestore',
        method: 'FIRQuery.addSnapshotListenerWithIncludeMetadataChanges:listener',
        path: meta.path,
        request: {
          type: 'listen',
          operation: 'querySnapshotListener',
          includeMetadataChanges,
          query: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRQuery snapshot listener record', function (snapshot, error) {
        const eventRecord = clonePlain(record);
        eventRecord.response = {
          error: errorPlain(error),
          querySnapshot: querySnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-query-listener-event', eventRecord);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRQuery', '- addSnapshotListenerWithOptions:listener:', {
    onEnter(args) {
      const meta = getFirestoreMeta(args[0]);
      const record = {
        kind: 'firestore',
        method: 'FIRQuery.addSnapshotListenerWithOptions:listener',
        path: meta.path,
        request: {
          type: 'listen',
          operation: 'querySnapshotListener',
          options: safeString(args[2]),
          query: meta
        }
      };
      logPendingTrace(record.method, record.path);
      wrapCompletionBlock(args[3], 'FIRQuery snapshot listener record', function (snapshot, error) {
        const eventRecord = clonePlain(record);
        eventRecord.response = {
          error: errorPlain(error),
          querySnapshot: querySnapshotPlain(snapshot)
        };
        const file = logTraceRecord('firestore-query-listener-event', eventRecord);
        return `path=${meta.path} full=${file}`;
      });
    }
  });

  attachMethod('FIRQuery', '- queryWhereField:isEqualTo:', {
    onEnter(args) {
      this.meta = getFirestoreMeta(args[0]);
      this.field = nsString(args[2]);
      this.value = objcToPlain(args[3], 0);
      log(`[FIRQuery whereEqual] ${this.meta.path}.${this.field} == ${JSON.stringify(this.value)}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
        filters: [{ field: this.field, op: '==', value: this.value }]
      }));
    }
  });

  [
    ['- queryWhereField:isNotEqualTo:', '!='],
    ['- queryWhereField:isGreaterThan:', '>'],
    ['- queryWhereField:isGreaterThanOrEqualTo:', '>='],
    ['- queryWhereField:isLessThan:', '<'],
    ['- queryWhereField:isLessThanOrEqualTo:', '<='],
    ['- queryWhereField:arrayContains:', 'array-contains'],
    ['- queryWhereField:arrayContainsAny:', 'array-contains-any'],
    ['- queryWhereField:notIn:', 'not-in']
  ].forEach(([selector, op]) => {
    attachMethod('FIRQuery', selector, {
      onEnter(args) {
        this.meta = getFirestoreMeta(args[0]);
        this.field = nsString(args[2]);
        this.value = objcToPlain(args[3], 0);
        log(`[FIRQuery where] ${this.meta.path}.${this.field} ${op} ${JSON.stringify(this.value)}`);
      },
      onLeave(retval) {
        rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
          filters: [{ field: this.field, op, value: this.value }]
        }));
      }
    });
  });

  [
    ['- queryWhereFieldPath:isEqualTo:', '=='],
    ['- queryWhereFieldPath:isNotEqualTo:', '!='],
    ['- queryWhereFieldPath:isGreaterThan:', '>'],
    ['- queryWhereFieldPath:isGreaterThanOrEqualTo:', '>='],
    ['- queryWhereFieldPath:isLessThan:', '<'],
    ['- queryWhereFieldPath:isLessThanOrEqualTo:', '<='],
    ['- queryWhereFieldPath:arrayContains:', 'array-contains'],
    ['- queryWhereFieldPath:arrayContainsAny:', 'array-contains-any'],
    ['- queryWhereFieldPath:in:', 'in'],
    ['- queryWhereFieldPath:notIn:', 'not-in']
  ].forEach(([selector, op]) => {
    attachMethod('FIRQuery', selector, {
      onEnter(args) {
        this.meta = getFirestoreMeta(args[0]);
        this.field = fieldArgToPlain(args[2]);
        this.value = objcToPlain(args[3], 0);
        log(`[FIRQuery whereFieldPath] ${this.meta.path}.${this.field} ${op} ${JSON.stringify(this.value)}`);
      },
      onLeave(retval) {
        rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
          filters: [{ fieldPath: this.field, op, value: this.value }]
        }));
      }
    });
  });

  attachMethod('FIRQuery', '- queryWhereField:in:', {
    onEnter(args) {
      this.meta = getFirestoreMeta(args[0]);
      this.field = nsString(args[2]);
      this.value = objcToPlain(args[3], 0);
      log(`[FIRQuery whereIn] ${this.meta.path}.${this.field} in ${JSON.stringify(this.value)}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
        filters: [{ field: this.field, op: 'in', value: this.value }]
      }));
    }
  });

  attachMethod('FIRQuery', '- queryLimitedTo:', {
    onEnter(args) {
      this.meta = getFirestoreMeta(args[0]);
      this.limit = args[2].toInt32();
      log(`[FIRQuery limit] ${this.meta.path} limit ${this.limit}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, queryMetaWith(this.meta, { limit: this.limit }));
    }
  });

  attachMethod('FIRQuery', '- queryLimitedToLast:', {
    onEnter(args) {
      this.meta = getFirestoreMeta(args[0]);
      this.limit = args[2].toInt32();
      log(`[FIRQuery limitToLast] ${this.meta.path} limitToLast ${this.limit}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
        limit: this.limit,
        limitToLast: true
      }));
    }
  });

  attachMethod('FIRQuery', '- queryOrderedByField:', {
    onEnter(args) {
      this.meta = getFirestoreMeta(args[0]);
      this.field = nsString(args[2]);
      log(`[FIRQuery orderBy] ${this.meta.path}.${this.field}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
        orderBy: [{ field: this.field, descending: false }]
      }));
    }
  });

  attachMethod('FIRQuery', '- queryOrderedByField:descending:', {
    onEnter(args) {
      this.meta = getFirestoreMeta(args[0]);
      this.field = nsString(args[2]);
      this.descending = !!args[3].toInt32();
      log(`[FIRQuery orderBy] ${this.meta.path}.${this.field} descending=${this.descending}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
        orderBy: [{ field: this.field, descending: this.descending }]
      }));
    }
  });

  attachMethod('FIRQuery', '- queryOrderedByFieldPath:', {
    onEnter(args) {
      this.meta = getFirestoreMeta(args[0]);
      this.field = fieldArgToPlain(args[2]);
      log(`[FIRQuery orderByFieldPath] ${this.meta.path}.${this.field}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
        orderBy: [{ fieldPath: this.field, descending: false }]
      }));
    }
  });

  attachMethod('FIRQuery', '- queryOrderedByFieldPath:descending:', {
    onEnter(args) {
      this.meta = getFirestoreMeta(args[0]);
      this.field = fieldArgToPlain(args[2]);
      this.descending = !!args[3].toInt32();
      log(`[FIRQuery orderByFieldPath] ${this.meta.path}.${this.field} descending=${this.descending}`);
    },
    onLeave(retval) {
      rememberFirestoreMeta(retval, queryMetaWith(this.meta, {
        orderBy: [{ fieldPath: this.field, descending: this.descending }]
      }));
    }
  });

  [
    ['- queryStartingAtValues:', 'startAt'],
    ['- queryStartingAfterValues:', 'startAfter'],
    ['- queryEndingBeforeValues:', 'endBefore'],
    ['- queryEndingAtValues:', 'endAt']
  ].forEach(([selector, boundType]) => {
    attachMethod('FIRQuery', selector, {
      onEnter(args) {
        this.meta = getFirestoreMeta(args[0]);
        this.values = objcToPlain(args[2], 0);
        log(`[FIRQuery bound] ${this.meta.path} ${boundType} ${JSON.stringify(this.values)}`);
      },
      onLeave(retval) {
        const change = {};
        change[boundType] = this.values;
        rememberFirestoreMeta(retval, queryMetaWith(this.meta, change));
      }
    });
  });
}

function hookFlutterFirePluginCalls() {
  const pluginClasses = Object.keys(ObjC.classes)
    .filter((name) => /^FLT.*Firebase|^FLTFirebase|^firebase_|^cloud_functions/.test(name))
    .sort();

  pluginClasses.forEach((className) => {
    const klass = ObjC.classes[className];
    klass.$ownMethods
      .filter((selector) => /handleMethodCall|methodCall|didReceive|call/i.test(selector))
      .forEach((selector) => {
        attachMethod(className, selector, {
          onEnter(args) {
            log(`[FlutterFire ${className} ${selector}] arg=${safeString(args[2])}`);
          }
        });
      });
  });
}

if (!ObjC.available) {
  log('ObjC runtime is not available in this process.');
} else {
  hookFlutterFirePluginCalls();
  hookFirebaseHighLevel();
  hookGTMSessionFetcher();

  [
    '- dataTaskWithRequest:completionHandler:',
    '- dataTaskWithURL:completionHandler:',
    '- uploadTaskWithRequest:fromData:completionHandler:',
    '- uploadTaskWithRequest:fromFile:completionHandler:',
    '- downloadTaskWithRequest:completionHandler:',
    '- downloadTaskWithURL:completionHandler:'
  ].forEach(hookURLSessionSelector);

  const hasStorage = !!ObjC.classes.FIRStorage;
  log(`[ready] Firebase trace installed. FIRStorage present=${hasStorage}. Trigger the failing flow now.`);

  if (ENABLE_NATIVE_NETWORK_TRACE) {
    hookNativeDartNetwork();
    log(`[ready] Native network trace installed. DNS=${LOG_NATIVE_DNS} connects=${LOG_NATIVE_CONNECTS} sni=${LOG_NATIVE_TLS_SNI}.`);
  }
}
