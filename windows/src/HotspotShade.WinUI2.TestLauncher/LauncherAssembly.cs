using System.Runtime.InteropServices;

// Load winhttp.dll and iphlpapi.dll from System32 only. Neither is a KnownDLL,
// so the default search would look in the launcher folder first, where a
// planted DLL would run inside the process that holds the bearer secret.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
