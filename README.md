# frida-flutterfire

Frida tools for inspecting Firebase and FlutterFire behavior in iOS apps when normal proxy tooling does not show the traffic. The main workflow is to run the Python wrapper, inject the Firebase tracer, and save decoded request/response artifacts to a host-side output directory.


## Usage Notes

Install Frida tools if needed:

```bash
python3 -m pip install frida-tools
```

Run the Firebase tracer against a USB-connected device and write decoded payloads to a timestamped output directory:

```bash
python3 run-firebase-trace.py -U -n "App Name"
# defaults to outputting at ./firebase-trace-output-$(date +%Y%m%d-%H%M%S)
```

Override the output directory for a specific flow:

```bash
python3 run-firebase-trace.py -U -n "App Name" -o ./traces/login-flow
python3 run-firebase-trace.py -U -f com.example.app -o /tmp/firebase-traces
```

Run the proxy check directly with Frida:

```bash
frida -U -f com.example.app -l ios-proxy-check.js
```

The default timestamped directory keeps runs from overwriting each other. `firebase-trace.js` does not write files directly on the device; `run-firebase-trace.py` watches for `__FIREBASE_TRACE_FILE__` markers and writes the decoded payloads into the generated directory or the directory passed with `-o/--out`.

# Scripts

### `run-firebase-trace.py`

Runs `firebase-trace.js` through Frida and writes emitted trace payloads to disk on the host machine. By default it creates a unique `firebase-trace-output-YYYYMMDD-HHMMSS/` directory; use `-o/--out` to override it.


### `firebase-trace.js`

Traces common Firebase and FlutterFire paths, including Firestore reads/writes/listeners, Auth, App Check, Installations, Functions, GTMSessionFetcher, and NSURLSession. It prints concise logs and emits larger request or response bodies as `__FIREBASE_TRACE_FILE__` markers containing base64 payloads. Not intended to be used directly but to be used with Python script.


### `ios-proxy-check.js`

Monitors request paths to see if they're respecting device proxy or not. It hooks socket connects, DNS lookups, `CFNetworkCopySystemProxySettings`, and `NSURLSession` request creation where available.
