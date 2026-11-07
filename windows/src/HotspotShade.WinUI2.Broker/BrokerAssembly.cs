using System.Runtime.InteropServices;

// Load kernel32, advapi32, shell32, winhttp, and iphlpapi from System32
// only. A DLL planted next to the broker must never load into the process
// that holds the engine bearer secrets.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
