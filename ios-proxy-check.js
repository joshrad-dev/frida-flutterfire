'use strict';

const CHARLES_HOSTS = new Set([
  '127.0.0.1',
  '::1',
  'localhost'
]);

const CHARLES_PORTS = new Set([
  8888,
  8889
]);

const HIDE_LOOPBACK_DNS_NOISE = true;

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
  if (addr.isNull()) return null;

  const len = readU8(addr);
  const family = readU8(addr.add(1));

  // AF_INET on Darwin.
  if (family === 2) {
    const port = ntohs(readU16(addr.add(2)));
    const ip = [
      readU8(addr.add(4)),
      readU8(addr.add(5)),
      readU8(addr.add(6)),
      readU8(addr.add(7))
    ].join('.');

    return {
      family: 'IPv4',
      host: ip,
      port,
      address: `${ip}:${port}`,
      len
    };
  }

  // AF_INET6 on Darwin.
  if (family === 30) {
    const port = ntohs(readU16(addr.add(2)));
    const parts = [];

    for (let i = 0; i < 8; i++) {
      parts.push(ntohs(readU16(addr.add(8 + i * 2))).toString(16));
    }

    const ip = parts.join(':');

    return {
      family: 'IPv6',
      host: ip,
      port,
      address: `[${ip}]:${port}`,
      len
    };
  }

  return {
    family: `unknown(${family})`,
    host: null,
    port: null,
    address: `family=${family}`,
    len
  };
}

function isLikelyCharles(dest) {
  if (!dest) return false;

  return CHARLES_PORTS.has(dest.port) &&
    (CHARLES_HOSTS.has(dest.host) || dest.host === '::1');
}

function logConnect(kind, dest) {
  if (!dest) return;

  const marker = isLikelyCharles(dest)
    ? 'PROXY'
    : dest.port === 443 || dest.port === 80
      ? 'DIRECT?'
      : 'OTHER';

  console.log(`[${kind}] ${marker} ${dest.address}`);
}

function attachExport(moduleName, exportName, callbacks) {
  let ptr = null;

  if (typeof Module.findExportByName === 'function') {
    ptr = Module.findExportByName(moduleName, exportName);
  } else if (moduleName === null && typeof Module.findGlobalExportByName === 'function') {
    ptr = Module.findGlobalExportByName(exportName);
  } else if (typeof Process.findModuleByName === 'function') {
    const module = Process.findModuleByName(moduleName);
    if (module && typeof module.findExportByName === 'function') {
      ptr = module.findExportByName(exportName);
    } else if (module && typeof module.getExportByName === 'function') {
      try {
        ptr = module.getExportByName(exportName);
      } catch (e) {
        ptr = null;
      }
    }
  }

  if (!ptr) {
    console.log(`[missing] ${exportName}`);
    return;
  }

  Interceptor.attach(ptr, callbacks);
  console.log(`[hooked] ${exportName}`);
}

function isNoisyLoopbackName(node) {
  return HIDE_LOOPBACK_DNS_NOISE &&
    typeof node === 'string' &&
    /^127\.0\.0\.1(?::\d+)?$/.test(node);
}

// Native socket path. This is the most useful one for Flutter/Dart.
attachExport(null, 'connect', {
  onEnter(args) {
    const dest = readSockaddr(args[1]);
    logConnect('connect', dest);
  }
});

// Some stacks use connectx on Darwin.
attachExport(null, 'connectx', {
  onEnter(args) {
    const endpoints = args[1];
    if (endpoints.isNull()) return;

    // struct sa_endpoints_t on 64-bit Darwin:
    // uint32 sae_srcif; padding; sockaddr *sae_srcaddr; socklen_t sae_srcaddrlen;
    // padding; sockaddr *sae_dstaddr; socklen_t sae_dstaddrlen;
    const dstaddrOffset = 24;
    const sockaddrPtr = readPointer(endpoints.add(dstaddrOffset));
    if (!sockaddrPtr.isNull()) {
      const dest = readSockaddr(sockaddrPtr);
      logConnect('connectx', dest);
    }
  }
});

// DNS visibility. Helpful for correlating origin names to later direct IP connects.
attachExport(null, 'getaddrinfo', {
  onEnter(args) {
    this.node = args[0].isNull() ? null : readUtf8String(args[0]);
    this.service = args[1].isNull() ? null : readUtf8String(args[1]);
  },
  onLeave(retval) {
    if (this.node && !isNoisyLoopbackName(this.node)) {
      console.log(`[getaddrinfo] ${this.node}${this.service ? ':' + this.service : ''} => ${retval.toInt32()}`);
    }
  }
});

// macOS/iOS system proxy lookup. If this never logs, the app may not even ask CFNetwork.
attachExport('CFNetwork', 'CFNetworkCopySystemProxySettings', {
  onLeave(retval) {
    if (retval.isNull()) {
      console.log('[CFNetworkCopySystemProxySettings] returned NULL');
      return;
    }

    try {
      console.log(`[CFNetworkCopySystemProxySettings] ${new ObjC.Object(retval).toString()}`);
    } catch (e) {
      console.log(`[CFNetworkCopySystemProxySettings] returned ${retval}`);
    }
  }
});

// Higher-level ObjC visibility if the app touches NSURLSession.
if (ObjC.available) {
  try {
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession && NSURLSession['- dataTaskWithRequest:completionHandler:']) {
      Interceptor.attach(
        NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation,
        {
          onEnter(args) {
            const req = new ObjC.Object(args[2]);
            console.log(`[NSURLSession dataTaskWithRequest] ${req.URL().absoluteString()}`);
          }
        }
      );
      console.log('[hooked] NSURLSession dataTaskWithRequest');
    }
  } catch (e) {
    console.log(`[objc hook error] ${e}`);
  }
}

console.log('[ready] Trigger network activity in the app now.');
console.log('[hint] If traffic respects Charles, connect/connectx should mostly go to 127.0.0.1:8888, ::1:8888, or your configured proxy host.');
