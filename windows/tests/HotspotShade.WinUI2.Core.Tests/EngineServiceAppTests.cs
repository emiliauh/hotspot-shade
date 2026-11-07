using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using HotspotShade.WinUI2.Core.Engine;
using HotspotShade.WinUI2.Core.Engine.Service;

namespace HotspotShade.WinUI2.Core.Tests
{
    // The app-side engine service integration checks. Every check drives the
    // real EngineServiceBroker, EngineSession, and EngineBoundary over a framed
    // in-memory channel to a real EngineServiceSession with a fake backend.
    // They open no pipe, service, process, route, or network endpoint.
    internal static class EngineServiceAppTests
    {
        private static readonly DateTimeOffset FixedNow =
            DateTimeOffset.FromUnixTimeSeconds(1800000000);

        public static void Run(TestRunner runner)
        {
            runner.Check("service app: mapped status passes the app reader", delegate
            {
                EngineServiceStatus status = ReadyStatus(FixedNow);
                EngineReply reply = EngineReply.Success(
                    EngineServiceBroker.MapStatus(status));

                EngineReply checkedReply;
                string code;
                AssertEx.True(
                    EngineWire.TryReadReply(reply.Fields, out checkedReply, out code),
                    "mapped status is a valid app reply: " + code);

                EngineStatus parsed;
                AssertEx.True(
                    EngineStatus.TryParse(checkedReply, FixedNow, out parsed, out code),
                    "mapped status parses: " + code);
                AssertEx.True(parsed.Paired, "paired");
                AssertEx.True(parsed.SourcePresent, "source present");
                AssertEx.True(parsed.ConnectionsKnown, "connections known");
                AssertEx.Equal(EngineCleanup.Ok, parsed.Cleanup, "cleanup gate");
                AssertEx.Equal(
                    FixedNow.AddSeconds(-1),
                    parsed.CheckedAt.Value,
                    "source check time");
                AssertEx.Equal(0, parsed.Connections, "stopped count");
            });

            runner.Check("service app: mapped status has only app fields and no credential", delegate
            {
                Dictionary<string, string> fields =
                    EngineServiceBroker.MapStatus(RunningStatus(FixedNow, 3));
                foreach (string key in fields.Keys)
                {
                    AssertEx.False(
                        EngineProtocol.IsCredentialKey(key),
                        "mapped status carries a credential key: " + key);
                }
                AssertEx.Equal(13, fields.Count, "mapped status field count");
                AssertEx.Equal("3", fields[EngineProtocol.Keys.Connections], "count");
                AssertEx.Equal("1", fields[EngineProtocol.Keys.ConnectionsKnown], "known");
                AssertEx.Equal("ok", fields[EngineProtocol.Keys.Cleanup], "cleanup word");
                AssertEx.Equal("0", fields[EngineProtocol.Keys.TtlBad], "ttl audit");
            });

            runner.Check("service app: ping display follows the active relay, not the request", delegate
            {
                EngineServiceStatus disabled = RunningStatus(FixedNow, 3);
                AssertEx.True(disabled.PingEnabled, "ping was requested");
                AssertEx.False(disabled.IcmpEnabled, "icmp relay is inactive");
                AssertEx.Equal("0", EngineServiceBroker.MapStatus(disabled)[EngineProtocol.Keys.Ping], "inactive relay");

                Dictionary<string, string> fields = disabled.ToFields();
                fields[EngineServiceStatusKeys.Version] = "1";
                fields[EngineServiceStatusKeys.IcmpEnabled] = "1";
                EngineServiceStatus enabled;
                string code;
                AssertEx.True(EngineServiceStatus.TryParse(fields, FixedNow, out enabled, out code), "active status: " + code);
                AssertEx.Equal("1", EngineServiceBroker.MapStatus(enabled)[EngineProtocol.Keys.Ping], "active relay");
            });

            runner.Check("service app: connect reads the real service status", delegate
            {
                Harness harness = new Harness(ReadyStatus(FixedNow));
                harness.Session.SetCredentialHeld(true);
                EngineCommandResult result = harness.Connect();
                AssertEx.True(result.Ok, "connect: " + result.Code);
                AssertEx.Equal(
                    EngineConnectionState.Available,
                    harness.Boundary.Session.Connection,
                    "connection");
                AssertEx.Equal(EngineBoundaryKind.Ready, harness.Boundary.Content.Kind, "kind");
                AssertEx.Equal("Off", harness.Boundary.Content.StatusText, "status text");
                AssertEx.Contains(
                    harness.Boundary.Content.PairingText,
                    "paired",
                    "pairing text");
                AssertEx.Contains(
                    harness.Boundary.Content.SourceText,
                    "present",
                    "source text");
                AssertEx.Contains(
                    harness.Boundary.Content.CheckedText,
                    "Checked at",
                    "check time");
                AssertEx.True(harness.Boundary.Content.CanStart, "start offered");
                AssertEx.False(harness.Boundary.Content.IsRunning, "no running claim");
                AssertEx.Equal(2, harness.Channel.Exchanges, "hello and status");
                AssertEx.False(harness.Channel.Closed, "channel stays open");
            });

            runner.Check("service app: a start is a request until a fresh status confirms On", delegate
            {
                Harness harness = new Harness(ReadyStatus(FixedNow));
                harness.Backend.RunningAfterStart = RunningStatus(FixedNow, 3);
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");

                EngineCommandResult start = harness.Start(true);
                AssertEx.True(start.Ok, "start ack: " + start.Code);
                AssertEx.False(start.Confirmed, "start is not confirmed");
                AssertEx.Equal(1, harness.Backend.Starts, "one backend start");
                AssertEx.True(harness.Backend.LastPing, "ping flag reached the backend");
                AssertEx.Equal(
                    EngineBoundaryKind.Checking,
                    harness.Boundary.Content.Kind,
                    "waiting for status");
                AssertEx.False(
                    harness.Boundary.Session.CanClaimRunning,
                    "no running claim from the ack");
                AssertEx.Equal("Unknown", harness.Boundary.Content.StatusText, "start has no confirmed state");

                EngineCommandResult refresh = harness.Refresh();
                AssertEx.True(refresh.Ok, "refresh: " + refresh.Code);
                AssertEx.True(
                    harness.Boundary.Session.CanClaimRunning,
                    "fresh status confirms On");
                AssertEx.Equal(EngineBoundaryKind.On, harness.Boundary.Content.Kind, "kind");
                AssertEx.Equal("Ping is off.", harness.Boundary.Content.PingText, "inactive relay is not displayed as on");
                AssertEx.Contains(
                    harness.Boundary.Content.ConnectionText,
                    "3",
                    "real connection count");
                AssertEx.Contains(
                    harness.Boundary.Content.CheckedText,
                    "Checked at",
                    "check time");
            });

            runner.Check("service app: an unpaired status never sends a start", delegate
            {
                Harness harness = new Harness(UnpairedStatus(FixedNow));
                AssertEx.True(harness.Connect().Ok, "connect");
                AssertEx.False(harness.Boundary.Content.CanStart, "no start offered");
                int before = harness.Channel.Exchanges;
                EngineCommandResult start = harness.Start(false);
                AssertEx.False(start.Ok, "start refused");
                AssertEx.Equal(
                    EngineProtocol.ErrorCodes.NotPaired,
                    start.Code,
                    "refusal code");
                AssertEx.Equal(before, harness.Channel.Exchanges, "no start frame");
                AssertEx.Equal(0, harness.Backend.Starts, "backend not called");
            });

            runner.Check("service app: stop shows the precise service stop sentence", delegate
            {
                Harness harness = new Harness(RunningStatus(FixedNow, 2));
                harness.Backend.StoppedAfterStop = StoppedStatus(
                    FixedNow,
                    EngineServiceCleanup.Ok,
                    EngineServiceStopReason.ServiceStop);
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");
                AssertEx.True(harness.Boundary.Content.IsRunning, "running first");

                EngineCommandResult stop = harness.Stop();
                AssertEx.True(stop.Ok, "stop ack: " + stop.Code);
                AssertEx.True(harness.Refresh().Ok, "refresh after stop");
                AssertEx.Equal(
                    EngineStopReason.ServiceStop,
                    harness.Boundary.Session.LastStopReason,
                    "stop reason");
                AssertEx.Contains(
                    harness.Boundary.Content.StopText,
                    "The tunnel service stopped.",
                    "precise stop text");
                AssertEx.Equal("Off", harness.Boundary.Content.StatusText, "off");
                AssertEx.False(harness.Boundary.Content.IsRunning, "no running claim");
            });

            runner.Check("service app: an observation failure keeps its exact sentence", delegate
            {
                Harness harness = new Harness(RunningStatus(FixedNow, 1));
                harness.Backend.StoppedAfterStop = StoppedStatus(
                    FixedNow,
                    EngineServiceCleanup.Ok,
                    EngineServiceStopReason.ObservationUnavailable);
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");
                AssertEx.True(harness.Stop().Ok, "stop");
                AssertEx.True(harness.Refresh().Ok, "refresh");
                AssertEx.Contains(
                    harness.Boundary.Content.StopText,
                    "does not mean the hotspot or the source device is gone",
                    "observation sentence");
            });

            runner.Check("service app: the cleanup gate blocks a start in the app", delegate
            {
                Harness harness = new Harness(StoppedStatus(
                    FixedNow,
                    EngineServiceCleanup.Failed,
                    EngineServiceStopReason.Unknown));
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");
                AssertEx.False(harness.Boundary.Content.CanStart, "no start offered");
                AssertEx.Equal(
                    EngineBoundaryKind.Attention,
                    harness.Boundary.Content.Kind,
                    "attention");
                AssertEx.Contains(
                    harness.Boundary.Content.Message,
                    "did not clean up its routes",
                    "cleanup message");
                AssertEx.Contains(
                    harness.Boundary.Content.StatusText,
                    "cleanup not confirmed",
                    "cleanup status");

                int before = harness.Channel.Exchanges;
                EngineCommandResult start = harness.Start(false);
                AssertEx.False(start.Ok, "start refused");
                AssertEx.Equal(
                    EngineProtocol.ErrorCodes.CleanupBlocked,
                    start.Code,
                    "cleanup code");
                AssertEx.Equal(before, harness.Channel.Exchanges, "no start frame");
                AssertEx.Equal(0, harness.Backend.Starts, "backend not called");
            });

            runner.Check("service app: an old source check makes the status unavailable", delegate
            {
                EngineServiceStatus stale = ReadyStatus(FixedNow, checkedAgoSeconds: 20);
                Harness harness = new Harness(stale);
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");
                AssertEx.Equal(
                    EngineFreshness.Unavailable,
                    harness.Boundary.Session.Freshness,
                    "freshness");
                AssertEx.Contains(
                    harness.Boundary.Content.Message,
                    "out of date",
                    "stale message");
                AssertEx.False(harness.Boundary.Content.CanStart, "no start offered");
                AssertEx.False(harness.Boundary.Content.IsRunning, "no running claim");
            });

            runner.Check("service app: an unknown count is shown as unknown, not zero", delegate
            {
                Harness harness = new Harness(RunningStatus(FixedNow, null));
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");
                AssertEx.True(harness.Boundary.Session.CanClaimRunning, "running");
                AssertEx.Contains(
                    harness.Boundary.Content.ConnectionText,
                    "Connections: unknown.",
                    "unknown count");
                AssertEx.DoesNotContain(
                    harness.Boundary.Content.ConnectionText,
                    "Connections: 0",
                    "no invented zero");
            });

            runner.Check("service app: a restarted service is refused, not shown as the old one", delegate
            {
                Harness harness = new Harness(ReadyStatus(FixedNow));
                AssertEx.True(harness.Connect().Ok, "connect");
                harness.Backend.Status = ReadyStatus(FixedNow, instance: "service-0002");
                EngineCommandResult refresh = harness.Refresh();
                AssertEx.False(refresh.Ok, "refresh refused");
                AssertEx.Equal(
                    EngineProtocol.ErrorCodes.EngineRestarted,
                    refresh.Code,
                    "restart code");
                AssertEx.Equal(
                    EngineBoundaryKind.Unavailable,
                    harness.Boundary.Content.Kind,
                    "unavailable");
                AssertEx.False(harness.Boundary.Content.IsRunning, "no running claim");
            });

            runner.Check("service app: a dropped start reply stays pending and a status confirms it", delegate
            {
                Harness harness = new Harness(ReadyStatus(FixedNow));
                harness.Backend.RunningAfterStart = RunningStatus(FixedNow, 1);
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");

                harness.Channel.DropNextReply = true;
                EngineCommandResult start = harness.Start(false);
                AssertEx.True(start.OutcomeUnknown, "ambiguous outcome");
                AssertEx.False(start.Ok, "not reported as applied");
                AssertEx.Equal(1, harness.Backend.Starts, "the service received the start");
                AssertEx.Equal(
                    EngineBoundaryKind.Checking,
                    harness.Boundary.Content.Kind,
                    "pending");
                AssertEx.False(
                    harness.Boundary.Session.CanClaimRunning,
                    "no running claim before a status");

                AssertEx.True(harness.Refresh().Ok, "refresh");
                AssertEx.True(
                    harness.Boundary.Session.CanClaimRunning,
                    "status confirms the applied start");
                AssertEx.Equal(1, harness.Backend.Starts, "the start is not replayed");
            });

            runner.Check("service app: close sends nothing and never restarts", delegate
            {
                Harness harness = new Harness(ReadyStatus(FixedNow));
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");
                harness.Boundary.Close();
                AssertEx.True(harness.Channel.Closed, "channel closed");

                EngineCommandResult start = harness.Start(false);
                AssertEx.False(start.Ok, "closed start refused");
                AssertEx.Equal(
                    EngineProtocol.ErrorCodes.Closed,
                    start.Code,
                    "closed code");
                AssertEx.Equal(0, harness.Backend.Starts, "no start after close");
                AssertEx.False(
                    EnginePollPolicy.ShouldPoll(
                        harness.Boundary.Session.Connection,
                        harness.Boundary.Session.IsClosed),
                    "no poll after close");
                AssertEx.Equal(0, harness.Backend.Stops, "close is not a tunnel stop");
            });

            runner.Check("service app: the app protocol still reads an old broker status", delegate
            {
                Dictionary<string, string> fields =
                    new Dictionary<string, string>(StringComparer.Ordinal);
                fields[EngineProtocol.Keys.Version] = "1";
                fields[EngineProtocol.Keys.Ok] = "1";
                fields[EngineProtocol.Keys.Instance] = "engine-0001";
                fields[EngineProtocol.Keys.Engine] = "ready";
                fields[EngineProtocol.Keys.Paired] = "1";
                fields[EngineProtocol.Keys.Running] = "0";
                fields[EngineProtocol.Keys.Source] = "1";
                fields[EngineProtocol.Keys.Trusted] = "1";
                fields[EngineProtocol.Keys.Ping] = "0";
                fields[EngineProtocol.Keys.Connections] = "0";
                fields[EngineProtocol.Keys.Stop] = "none";

                EngineReply reply;
                string code;
                AssertEx.True(
                    EngineWire.TryReadReply(fields, out reply, out code),
                    "old reply: " + code);
                EngineStatus status;
                AssertEx.True(
                    EngineStatus.TryParse(reply, FixedNow, out status, out code),
                    "old status: " + code);
                AssertEx.True(status.ConnectionsKnown, "known by default");
                AssertEx.Equal(EngineCleanup.Ok, status.Cleanup, "clean by default");
                AssertEx.False(status.CheckedAt.HasValue, "no source time by default");
                AssertEx.Equal(
                    EngineFreshness.Fresh,
                    status.FreshnessAt(FixedNow),
                    "sample freshness unchanged");
            });

            runner.Check("service app: checked_at format and skew are bounded", delegate
            {
                DateTimeOffset? parsed;
                AssertEx.True(
                    EngineWire.TryParseCheckedAt("", FixedNow, out parsed),
                    "empty is absent");
                AssertEx.False(parsed.HasValue, "absent value");
                AssertEx.False(
                    EngineWire.TryParseCheckedAt("abc", FixedNow, out parsed),
                    "letters refused");
                AssertEx.False(
                    EngineWire.TryParseCheckedAt("-1", FixedNow, out parsed),
                    "negative refused");
                AssertEx.False(
                    EngineWire.TryParseCheckedAt(
                        FixedNow.AddSeconds(301).ToUnixTimeSeconds()
                            .ToString(CultureInfo.InvariantCulture),
                        FixedNow,
                        out parsed),
                    "future beyond the skew refused");
                AssertEx.True(
                    EngineWire.TryParseCheckedAt(
                        FixedNow.AddSeconds(-1).ToUnixTimeSeconds()
                            .ToString(CultureInfo.InvariantCulture),
                        FixedNow,
                        out parsed),
                    "recent value accepted");
                AssertEx.Equal(FixedNow.AddSeconds(-1), parsed.Value, "parsed time");

                Dictionary<string, string> fields = AppStatusFields();
                fields[EngineProtocol.Keys.CheckedAt] = "abc";
                EngineReply reply;
                string code;
                AssertEx.False(
                    EngineWire.TryReadReply(fields, out reply, out code),
                    "malformed checked_at refused");
                AssertEx.Equal(
                    EngineProtocol.ErrorCodes.BadResponse,
                    code,
                    "refusal code");
            });

            runner.Check("service app: an unknown count with a value is inconsistent", delegate
            {
                Dictionary<string, string> fields = AppStatusFields();
                fields[EngineProtocol.Keys.Running] = "1";
                fields[EngineProtocol.Keys.Engine] = "running";
                fields[EngineProtocol.Keys.Connections] = "2";
                fields[EngineProtocol.Keys.ConnectionsKnown] = "0";
                fields[EngineProtocol.Keys.Ping] = "1";

                EngineReply reply;
                string code;
                AssertEx.True(
                    EngineWire.TryReadReply(fields, out reply, out code),
                    "shape: " + code);
                EngineStatus status;
                AssertEx.False(
                    EngineStatus.TryParse(reply, FixedNow, out status, out code),
                    "unknown count with a value refused");
            });

            runner.Check("service app: a TTL audit failure is shown beside a running tunnel", delegate
            {
                EngineServiceStatus audited = BuildStatus(
                    FixedNow,
                    "service-0001",
                    true,
                    true,
                    true,
                    2,
                    EngineServiceCleanup.Ok,
                    EngineServiceStopReason.None,
                    1,
                    ttlBad: 2);
                Harness harness = new Harness(audited);
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");
                AssertEx.True(harness.Boundary.Content.IsRunning, "tunnel is on");
                AssertEx.Equal(EngineBoundaryKind.Attention, harness.Boundary.Content.Kind, "kind");
                AssertEx.Contains(
                    harness.Boundary.Content.Message,
                    "2 wrong TTL read-backs",
                    "audit count");
                AssertEx.Contains(
                    harness.Boundary.Content.AccessibilityText,
                    "wrong TTL",
                    "screen reader text");
            });

            runner.Check("service app: a stopped tunnel does not claim a current TTL failure", delegate
            {
                EngineServiceStatus audited = BuildStatus(
                    FixedNow, "service-0001", false, false, false, null,
                    EngineServiceCleanup.Ok, EngineServiceStopReason.None, 0, ttlBad: 2);
                Harness harness = new Harness(audited);
                AssertEx.True(harness.Connect().Ok, "connect");
                AssertEx.Equal("Off", harness.Boundary.Content.StatusText, "stopped status");
                AssertEx.False(harness.Boundary.Content.Title == "Engine: TTL audit failed", "no active failure");
            });

            runner.Check("service app: a failed stop reply is not a clean stop", delegate
            {
                Harness harness = new Harness(RunningStatus(FixedNow, 1));
                harness.Backend.StoppedAfterStop = StoppedStatus(
                    FixedNow,
                    EngineServiceCleanup.Failed,
                    EngineServiceStopReason.User);
                harness.Session.SetCredentialHeld(true);
                AssertEx.True(harness.Connect().Ok, "connect");
                harness.Channel.DropNextReply = true;
                EngineCommandResult stop = harness.Stop();
                AssertEx.True(stop.OutcomeUnknown, "ambiguous stop");
                AssertEx.False(stop.Ok, "not a clean stop");
                AssertEx.Equal(1, harness.Backend.Stops, "one backend stop");
                AssertEx.False(
                    harness.Boundary.Session.CanClaimRunning,
                    "no running claim after an ambiguous stop");
            });
        }

        private static Dictionary<string, string> AppStatusFields()
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineProtocol.Keys.Version] = "1";
            fields[EngineProtocol.Keys.Ok] = "1";
            fields[EngineProtocol.Keys.Instance] = "engine-0001";
            fields[EngineProtocol.Keys.Engine] = "ready";
            fields[EngineProtocol.Keys.Paired] = "1";
            fields[EngineProtocol.Keys.Running] = "0";
            fields[EngineProtocol.Keys.Source] = "1";
            fields[EngineProtocol.Keys.Trusted] = "1";
            fields[EngineProtocol.Keys.Ping] = "0";
            fields[EngineProtocol.Keys.Connections] = "0";
            fields[EngineProtocol.Keys.Stop] = "none";
            return fields;
        }

        private static EngineServiceStatus ReadyStatus(
            DateTimeOffset now,
            int checkedAgoSeconds = 1,
            string instance = "service-0001")
        {
            return BuildStatus(
                now,
                instance,
                false,
                true,
                true,
                null,
                EngineServiceCleanup.Ok,
                EngineServiceStopReason.None,
                checkedAgoSeconds);
        }

        private static EngineServiceStatus RunningStatus(
            DateTimeOffset now,
            int? relayConnections)
        {
            return BuildStatus(
                now,
                "service-0001",
                true,
                true,
                true,
                relayConnections,
                EngineServiceCleanup.Ok,
                EngineServiceStopReason.None,
                1);
        }

        private static EngineServiceStatus UnpairedStatus(DateTimeOffset now)
        {
            return BuildStatus(
                now,
                "service-0001",
                false,
                false,
                false,
                null,
                EngineServiceCleanup.Ok,
                EngineServiceStopReason.None,
                0);
        }

        private static EngineServiceStatus StoppedStatus(
            DateTimeOffset now,
            EngineServiceCleanup cleanup,
            EngineServiceStopReason stop)
        {
            return BuildStatus(
                now,
                "service-0001",
                false,
                false,
                false,
                null,
                cleanup,
                stop,
                0);
        }

        private static EngineServiceStatus BuildStatus(
            DateTimeOffset now,
            string instance,
            bool running,
            bool paired,
            bool sourcePresent,
            int? relayConnections,
            EngineServiceCleanup cleanup,
            EngineServiceStopReason stop,
            int checkedAgoSeconds,
            int ttlBad = 0)
        {
            Dictionary<string, string> fields = new Dictionary<string, string>(StringComparer.Ordinal);
            fields[EngineServiceStatusKeys.Version] = "1";
            fields[EngineServiceStatusKeys.Ok] = "1";
            fields[EngineServiceStatusKeys.Instance] = instance;
            fields[EngineServiceStatusKeys.Engine] = running ? "running" : "ready";
            fields[EngineServiceStatusKeys.Running] = Word(running);
            fields[EngineServiceStatusKeys.Mode] = "phone";
            fields[EngineServiceStatusKeys.Paired] = Word(paired);
            fields[EngineServiceStatusKeys.PairedScope] = paired ? "session" : "none";
            fields[EngineServiceStatusKeys.Source] = Word(sourcePresent);
            fields[EngineServiceStatusKeys.Trusted] = Word(sourcePresent);
            fields[EngineServiceStatusKeys.CheckedAt] = sourcePresent
                ? now.AddSeconds(-checkedAgoSeconds)
                    .ToUnixTimeSeconds()
                    .ToString(CultureInfo.InvariantCulture)
                : "";
            fields[EngineServiceStatusKeys.Ping] = Word(running);
            fields[EngineServiceStatusKeys.IcmpEnabled] = "0";
            fields[EngineServiceStatusKeys.PhoneConnections] = "";
            fields[EngineServiceStatusKeys.PhoneConnectionsKnown] = "0";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActive] = relayConnections.HasValue
                ? relayConnections.Value.ToString(CultureInfo.InvariantCulture)
                : "";
            fields[EngineServiceStatusKeys.RelayTcpFlowsActiveKnown] =
                Word(relayConnections.HasValue);
            fields[EngineServiceStatusKeys.TtlBad] = ttlBad.ToString(CultureInfo.InvariantCulture);
            fields[EngineServiceStatusKeys.Ipv6Dropped] = "0";
            fields[EngineServiceStatusKeys.FragmentsDropped] = "0";
            fields[EngineServiceStatusKeys.Stop] = EngineServiceStatus.StopWord(stop);
            fields[EngineServiceStatusKeys.StopAt] = stop == EngineServiceStopReason.None
                ? ""
                : now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            // A running service status must report an unknown cleanup gate; a
            // stopped one carries the real gate.
            fields[EngineServiceStatusKeys.Cleanup] = running
                ? "unknown"
                : CleanupWord(cleanup);
            fields[EngineServiceStatusKeys.Admin] = "1";

            EngineServiceStatus status;
            string code;
            AssertEx.True(
                EngineServiceStatus.TryParse(fields, now, out status, out code),
                "service status: " + code);
            return status;
        }

        private static string CleanupWord(EngineServiceCleanup cleanup)
        {
            switch (cleanup)
            {
                case EngineServiceCleanup.Failed:
                    return "failed";
                case EngineServiceCleanup.Pending:
                    return "pending";
                case EngineServiceCleanup.Unknown:
                    return "unknown";
                default:
                    return "ok";
            }
        }

        private static string Word(bool value)
        {
            return value ? "1" : "0";
        }

        private sealed class Harness
        {
            public readonly DateTimeOffset Now = FixedNow;
            public readonly FakeBackend Backend;
            public readonly EngineServiceSession Session;
            public readonly SessionChannel Channel;
            public readonly EngineBoundary Boundary;

            public Harness(EngineServiceStatus status)
            {
                Backend = new FakeBackend(status);
                Session = new EngineServiceSession(
                    "service-0001",
                    Backend,
                    new FixedClock(Now),
                    EngineServiceStateGate.FromRecord(
                        EngineServiceStateRecord.CreateNeverLaunched(Now)));
                Channel = new SessionChannel(Session);
                EngineServiceBroker broker = new EngineServiceBroker(
                    Channel,
                    new FixedClock(Now),
                    TimeSpan.FromSeconds(2));
                Boundary = new EngineBoundary(
                    broker,
                    new FixedClock(Now),
                    TimeSpan.FromSeconds(2));
            }

            public EngineCommandResult Connect()
            {
                return Wait(Boundary.ConnectAsync());
            }

            public EngineCommandResult Refresh()
            {
                return Wait(Boundary.PollAsync());
            }

            public EngineCommandResult Start(bool ping)
            {
                return Wait(Boundary.StartAsync(ping));
            }

            public EngineCommandResult Stop()
            {
                return Wait(Boundary.StopAsync());
            }

            private static EngineCommandResult Wait(Task<EngineCommandResult> task)
            {
                return task.GetAwaiter().GetResult();
            }
        }

        private sealed class FixedClock : IEngineClock
        {
            public FixedClock(DateTimeOffset now)
            {
                Now = now;
            }

            public DateTimeOffset Now { get; private set; }
        }

        private sealed class FakeBackend : IEngineServiceBackend
        {
            public FakeBackend(EngineServiceStatus status)
            {
                Status = status;
            }

            public EngineServiceStatus Status;
            public EngineServiceStatus RunningAfterStart;
            public EngineServiceStatus StoppedAfterStop;
            public int Starts;
            public int Stops;
            public bool LastPing;

            public EngineServiceStatus ReadStatus()
            {
                return Status;
            }

            public EngineServiceResult Start(bool ping)
            {
                Starts++;
                LastPing = ping;
                if (RunningAfterStart != null)
                {
                    Status = RunningAfterStart;
                }
                return EngineServiceResult.Success();
            }

            public EngineServiceResult Stop(EngineServiceStopReason reason)
            {
                Stops++;
                if (StoppedAfterStop != null)
                {
                    Status = StoppedAfterStop;
                }
                return EngineServiceResult.Success();
            }
        }

        private sealed class SessionChannel : IEngineServiceChannel
        {
            private readonly EngineServiceSession session;

            public SessionChannel(EngineServiceSession session)
            {
                this.session = session;
            }

            public bool DropNextReply;
            public int Exchanges;
            public bool Closed;

            public async Task<byte[]> ExchangeAsync(
                byte[] requestFrame,
                CancellationToken cancellationToken)
            {
                Interlocked.Increment(ref Exchanges);
                Dictionary<string, string> fields;
                string code;
                if (!EngineServiceFrame.TryDecode(
                    requestFrame,
                    requestFrame.Length,
                    out fields,
                    out code))
                {
                    return null;
                }
                EngineReply reply = await session.HandleAsync(fields, cancellationToken)
                    .ConfigureAwait(false);
                if (DropNextReply)
                {
                    DropNextReply = false;
                    return null;
                }
                byte[] frame;
                if (!EngineServiceFrame.TryEncode(reply.Fields, out frame, out code))
                {
                    return null;
                }
                return frame;
            }

            public Task CloseAsync()
            {
                Closed = true;
                return Task.CompletedTask;
            }
        }
    }
}
