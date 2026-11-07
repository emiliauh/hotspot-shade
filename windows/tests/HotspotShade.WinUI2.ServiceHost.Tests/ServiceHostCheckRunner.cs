using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotspotShade.WinUI2.ServiceHost.Tests
{
    internal sealed class ServiceHostCheckRunner
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
                Console.WriteLine("ALL WINDOWS SERVICE HOST FOUNDATION CHECKS PASSED");
                return 0;
            }
            Console.WriteLine("WINDOWS SERVICE HOST FOUNDATION CHECKS FAILED");
            for (int index = 0; index < failures.Count; index++)
            {
                Console.WriteLine(" - " + failures[index]);
            }
            return 1;
        }
    }

    internal static class ServiceHostAssert
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

        public static void Throws<TException>(Action body, string what)
            where TException : Exception
        {
            try
            {
                body();
            }
            catch (TException)
            {
                return;
            }
            throw new Exception(what + ": expected " + typeof(TException).Name + ".");
        }

        public static T Wait<T>(Task<T> task, int milliseconds, string what)
        {
            if (!task.Wait(milliseconds))
            {
                throw new Exception(what + ": timed out.");
            }
            return task.Result;
        }

        public static void Wait(Task task, int milliseconds, string what)
        {
            if (!task.Wait(milliseconds))
            {
                throw new Exception(what + ": timed out.");
            }
        }
    }
}
