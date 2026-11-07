# Windows engine service executable

Status: **UNAPPROVED. NOT INSTALLED. NOT WIRED TO THE APP.
NOT PRODUCTION READY. NO TUNNEL IS CLAIMED.**

This project turns the service-host foundation into a runnable Windows
Service Control Manager (SCM) process. It is the process boundary only. It
does not install a service, start a service, change the service
configuration, create an adapter, add a route, open a socket, or launch an
engine.

The assembly name is `HotspotShadeEngineSvc`. The SCM service name is
`HotspotShadeEngineSvc` from `EngineServiceBoundary.ServiceName`. The build is
declared x64 only. A Windows x64 host must build and publish the service image.
A build on another host proves compilation only.

## What this project does

- `Program` connects the process to the SCM with
  `StartServiceCtrlDispatcherW`. A console launch is refused with the
  documented `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` result and a fixed
  message.
- `EngineServiceScmService` registers one control handler with
  `RegisterServiceCtrlHandlerExW` before it reports any state.
- `EngineServiceScmStatusReporter` maps the existing `EngineServiceHostState`
  values to `SERVICE_STATUS` records and calls `SetServiceStatus`. Pending
  states carry a nonzero checkpoint and the host wait hint. Running accepts
  stop and shutdown. Stopped accepts no control.
- A stop or shutdown control cancels one linked token, reports StopPending, and
  records one fixed event. Cancellation callbacks run on the control thread
  and must not block. A second stop control does not run a second
  cancellation. Interrogate is accepted. Pause, continue, and custom controls
  are refused with `ERROR_CALL_NOT_IMPLEMENTED`, and the live session is not
  changed.
- A stop that arrives before the host reports Running is reported as
  StopPending. The reporter never sends a backwards StartPending or Running
  record after a stop request.
- The host's final Stopped record is held until `TryFinalize`. That single
  record carries the fixed service-specific exit code, so a failed startup is
  visible to the SCM and to a person without a log that could hold a path,
  SID, or token.
- `EngineServiceComposition` builds the real seams: the installed account
  gate, the durable state gate, the caller policy, the named-pipe server
  factory, the session gate, the guarded backend, and one host generation.
- `EngineServiceFileStateStore` reads one bounded `EngineServiceFrame` object
  from the install-time state file. It is read-only. It refuses a missing,
  empty, oversized, or unreadable file, a directory, a leaf reparse point, a
  short read, a file that grows during the read, trailing bytes, and any field
  the core state parser refuses.
- `EngineServiceComposition` accepts an `IEngineControlChannelFactory`. The
  default factory is unavailable, so the guarded backend refuses a start with
  `engine_unavailable`. A reviewed launcher can inject a factory that returns
  the private control, liveness, and key channels. The composition then builds
  an authenticated `EngineControlSession` and an `EngineControlStatusSource`.
  The session is lazy: it connects on the first status read.
- The control session can read status and run one authenticated stop. Every
  start is still refused by `GuardedEngineServiceBackend.SourceProxyStartEnabled`
  and the Rust source-proxy guard is untouched. No launcher, pipe create, or
  process start exists in this project.

## Configuration

The installer puts these arguments on the service image command line
(`lpBinaryPathName`) in the service record. The CLR turns that command line
into the process arguments, and the service reads them there. The SCM service
main vector carries the service name and any `StartService` parameters, not
this configuration, so the service does not parse that vector. Every option is
required exactly once. An unknown option, a duplicate option, a missing value,
a relative path, a UNC path, and a non-user account form are refused before a
pipe exists.

| Option | Meaning |
|---|---|
| `--instance` | The service instance id from the host contract. |
| `--installed-user-sid` | The installing person's user SID. It must pass the user-form check. The host also requires `LookupAccountSid` to report a user account. |
| `--service-binary` | The installed service image path. The app-side proof compares it. |
| `--engine-image` | The installed engine image path. The durable state record must name the same image. |
| `--state-file` | The read-only durable state frame under the protected install directory. |

The values are not secrets. The source device token, the identity key, and
every bearer secret are never accepted on this command line. The installer
must create the state file with a never-launched record before the first
start. This project has no writer.

## Exit codes

A nonzero exit is paired with `ERROR_SERVICE_SPECIFIC_ERROR` in the final
`SERVICE_STATUS`. These codes are the startup record. This build writes no
event log and no log file, so it cannot leak a path, SID, or token through a
log.

| Code | Meaning |
|---|---|
| 0 | Clean stop, or a requested stop before a generation ran. |
| 1 | Invalid service configuration. |
| 2 | Not Windows, or the SCM did not start the process. |
| 3 | The installed account was refused. |
| 4 | The durable state is missing, unreadable, pending, or blocked. |
| 5 | The named pipe name is already in use. |
| 6 | The stop budget expired. |
| 7 | An internal adapter failure. |
| 8 | The engine or its control channel is unavailable. |
| 9 | A failed caller revert disabled the generation. |
| 10 | The generation failed without a more specific fixed class. |

## What remains

- No service installation, `CreateService`, `StartService`, `sc.exe`,
  service security descriptor applied to a live service, installer, or
  uninstaller.
- No Windows host run. The SCM calls, the status transitions, the handler, and
  the stop path have never run on Windows. The hermetic checks use a fake
  status sink, a fake factory, and a fake generation. The state-store checks
  use a temporary file. No pipe, service, process, route, or device is
  created.
- No launcher, launch gate, process handle, final frame, adapter identity, or
  route cleanup. The authenticated control client and status source exist, but
  the default channel factory is unavailable. A reviewed launcher must create
  the private channels and key, start the installed engine image, and return
  the service ends. The guarded backend still refuses every start.
- No Rust engine-side `ControlHandler`. The service client is ready for the
  `Status`, `Start`, and `Stop` commands, but the engine side is not wired.
- No process identity proof for a previous engine. A stopped durable record
  therefore fails closed, because absence of a process id cannot be proven
  without the creation time check.
- No write path, protected `%ProgramData%` ACL, parent-directory reparse
  check, flush, or atomic replace for the state file. The leaf reparse check
  and bounded read are input checks, not ownership proof.
- No app wiring. The UWP app does not load this project. The project is
  not in `windows/HotspotShade.WinUI2.sln`. Its hermetic tests run in CI.
- The .NET 8 target is the same runtime as the existing foundation. The
  service design recommends .NET 10 LTS. That decision remains open.
- No signed package, publisher pinning, live source device test, or hotspot
  test.

## Build and test on a non-Windows host

These commands compile the code and run fake-backed checks. They do not
produce a Windows apphost and do not run a service.

```text
dotnet build windows/src/HotspotShade.WinUI2.Service/HotspotShade.WinUI2.Service.csproj -c Release
dotnet run --project windows/tests/HotspotShade.WinUI2.ServiceHost.Tests/HotspotShade.WinUI2.ServiceHost.Tests.csproj -c Release
```

Expected: the build has no warnings, and the test runner prints
`ALL WINDOWS SERVICE HOST FOUNDATION CHECKS PASSED` with the SCM checks in the
list. A pass is not a Windows host result, a service install, an SCM dispatch,
a named pipe, or a tunnel.

On a Windows x64 host, the service image is produced with:

```text
dotnet publish windows/src/HotspotShade.WinUI2.Service/HotspotShade.WinUI2.Service.csproj -c Release -r win-x64
```

This tree does not run that command and does not install the result.

## Review request

An independent reviewer should answer these questions before enablement:

1. Is the handler registered before any status report, and is every status
   record a documented transition from the previous one?
2. Does a stop that wins before Running avoid a backwards StartPending or
   Running record?
3. Is exactly one Stopped record sent, with `ERROR_SERVICE_SPECIFIC_ERROR` for
   a fixed nonzero exit code?
4. Does a stop, shutdown, interrogate, pause, or custom control leave the live
   session untouched except for the documented stop and interrogate cases?
5. Is there no install, service-start, route, adapter, socket, or engine
   launch call?
6. Does the configuration accept no secret and no caller-named pipe or
   endpoint?
7. Does the file store refuse every unreadable, untrusted, or ambiguous
   record before the host creates a pipe?
8. Are the existing installed-account, durable-state, session-state, caller,
   payload, and source-proxy gates still in force?
