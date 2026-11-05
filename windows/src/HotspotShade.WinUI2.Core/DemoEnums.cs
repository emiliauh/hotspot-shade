namespace HotspotShade.WinUI2.Core
{
    // The simulated screen that the demo shows. The values match the macOS
    // target app states, but every value here is local demo data.
    public enum DemoScenario
    {
        Unpaired,
        PairingCode,
        PairingFailed,
        NotTrusted,
        Waiting,
        Ready,
        On,
        OnSourceStopped,
        OnNotTrusted,
        Stale,
        Unavailable,
        Error,
        ActivityEmpty,
        ForgetConfirmed
    }

    // The color family of the status mark. The text always says the state.
    public enum DemoStatusKind
    {
        Off,
        On,
        Attention,
        Pairing,
        Busy
    }

    // The status mark family. Busy uses the pairing mark.
    public enum DemoStatusDot
    {
        Off,
        On,
        Attention,
        Pairing
    }

    // The one main action on the dashboard.
    public enum DemoPrimaryAction
    {
        None,
        Pair,
        PairAgain,
        TurnOn,
        TurnOff,
        Retry,
        CheckNow
    }

    // The optional second action on the dashboard.
    public enum DemoSecondaryAction
    {
        None,
        Forget,
        TurnOffAndForget,
        CheckNow
    }

    // An action that one attention line can offer.
    public enum DemoAttentionAction
    {
        None,
        CheckNow,
        TurnOff,
        TurnOffAndForget
    }

    public enum DemoPairingPhase
    {
        Idle,
        Starting,
        Confirming,
        Failed,
        Paired
    }

    public enum DemoForgetState
    {
        None,
        Pending,
        Confirmed,
        NotDelivered
    }

    public enum DemoActivityState
    {
        Loading,
        Loaded,
        Empty,
        Unavailable
    }

    public enum DemoFailuresState
    {
        Idle,
        Loading,
        Loaded,
        Empty,
        Unavailable,
        Error
    }

    // The setup stage of a simulated source device connection. An older engine
    // sends no stage. A newer engine can send a word that this app does not
    // know.
    public enum DemoFailurePhase
    {
        NotReported,
        Connect,
        Greeting,
        Auth,
        Request,
        Unknown
    }

    // The settings values. The order matches the Windows settings picker.
    public enum DemoTheme
    {
        System,
        Light,
        Dark
    }

    // The one delayed demo action. The page runs a local timer. No work runs
    // in the background and no service is present.
    public enum DemoPendingAction
    {
        None,
        PairingStart,
        TunnelStart,
        TunnelStop,
        CheckNow,
        ForgetAfterStop,
        RefreshActivity,
        LoadFailures
    }

    // How much this app can trust the last simulated status.
    public enum DemoFreshness
    {
        Fresh,
        Stale,
        Unavailable
    }
}
