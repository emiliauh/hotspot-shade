using System;
using System.Collections.Generic;

namespace HotspotShade.WinUI2.Core.Tests
{
    internal sealed class TestRunner
    {
        private readonly List<string> failures = new List<string>();

        public int Passed { get; private set; }

        public int Failed
        {
            get { return failures.Count; }
        }

        public void Check(string name, Action body)
        {
            try
            {
                body();
                Passed++;
                Console.WriteLine("PASS " + name);
            }
            catch (Exception error)
            {
                failures.Add(name + ": " + error.Message);
                Console.WriteLine("FAIL " + name);
                Console.WriteLine("     " + error.Message);
            }
        }

        public int Finish()
        {
            Console.WriteLine("");
            Console.WriteLine("Passed: " + Passed);
            Console.WriteLine("Failed: " + Failed);
            if (Failed == 0)
            {
                Console.WriteLine("ALL WINUI2 PROTOTYPE CHECKS PASSED");
                return 0;
            }
            Console.WriteLine("WINUI2 PROTOTYPE CHECKS FAILED");
            for (int index = 0; index < failures.Count; index++)
            {
                Console.WriteLine(" - " + failures[index]);
            }
            return 1;
        }
    }

    internal static class AssertEx
    {
        public static void Equal<T>(T expected, T actual, string what)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new Exception(what + ": expected <" + expected + ">, got <" + actual + ">.");
            }
        }

        public static void True(bool condition, string what)
        {
            if (!condition)
            {
                throw new Exception(what);
            }
        }

        public static void False(bool condition, string what)
        {
            True(!condition, what);
        }

        public static void Contains(string text, string part, string what)
        {
            if (text == null || text.IndexOf(part, StringComparison.Ordinal) < 0)
            {
                throw new Exception(what + ": missing <" + part + "> in <" + text + ">.");
            }
        }

        public static void DoesNotContain(string text, string part, string what)
        {
            if (text != null && text.IndexOf(part, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                throw new Exception(what + ": found <" + part + "> in <" + text + ">.");
            }
        }

        public static void NotEmpty(string text, string what)
        {
            True(!string.IsNullOrWhiteSpace(text), what + " is empty.");
        }
    }

    internal sealed class FakeClock : IDemoClock
    {
        public FakeClock(DateTimeOffset now)
        {
            Now = now;
        }

        public DateTimeOffset Now { get; set; }

        public void Advance(double seconds)
        {
            Now = Now.AddSeconds(seconds);
        }
    }
}
