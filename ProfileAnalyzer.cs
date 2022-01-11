// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Text;
using Microsoft.Windows.EventTracing.Cpu;
using Microsoft.Windows.EventTracing.Symbols;

namespace IdleWakeups
{
  internal class ProfileAnalyzer
  {
    public struct Options
    {
      public string EtlFileName { get; set; }
      public decimal TimeStart { get; set; }
      public decimal TimeEnd { get; set; }
      public HashSet<string> ProcessFilterSet { get; set; }
      public bool Tabbed { get; set; }
      public bool Verbose { get; set; }
    }

    private struct IdleWakeup
    {
      public long ContextSwitchCount { get; set; }
      public long ContextSwitchDPCCount { get; set; }
      public int ProcessId { get; set; }
      public string ProcessName { get; set; }
      public ChromeProcessType ProcessType { get; set; }
      public string ThreadName { get; set; }
      public Dictionary<string, StackFrames> ReadyingThreadStacks { get; set; }
      public Dictionary<string, StackFrames> ReadiedThreadStacks { get; set; }
    }

    private struct ChromeProcessType
    {
      public ChromeProcessType(string type, string? subType)
      {
        Type = type;
        SubType = subType;
      }
      public string Type { get; set; }

      public string? SubType { get; set; }
    }

    private struct StackFrames
    {
      public long StackCount { get; set; }
      public long StackDPCCount { get; set; }
      public IReadOnlyList<StackFrame> Stack { get; set; }
    }

    public ProfileAnalyzer(Options options)
    {
      _options = options;
    }

    public void AddSample(ICpuThreadActivity sample)
    {
      // A context switch is the act of moving the New Thread from Ready to Running, and moving
      // the Old Thread from Running to some other state, on a particular CPU. We are focusing on
      // a special type of context switches, namely idle wakeups where the Old Thread is the idle
      // thread.
      var contextSwitch = sample.SwitchIn.ContextSwitch;

      // Ignore samples that are outside any given time interval.
      var timestamp = contextSwitch.Timestamp.RelativeTimestamp.TotalSeconds;
      if (timestamp < _options.TimeStart || timestamp > _options.TimeEnd)
      {
        return;
      }

      var switchInImageName = contextSwitch.SwitchIn.Process.ImageName;
      var switchOutImageName = contextSwitch.SwitchOut.Process.ImageName;

      // Check if all processes shall be analyzed when switched in (filter set to '*') or if a
      // filter has been set (e.g. 'chrome.exe') and it contains the process name switching in.
      if (_options.ProcessFilterSet == null ||
          _options.ProcessFilterSet.Contains(switchInImageName))
      {
        _wallTimeStart = Math.Min(_wallTimeStart, timestamp);
        _wallTimeEnd = Math.Max(_wallTimeEnd, timestamp);

        // A context switch was detected but we don't yet know if it is an idle wakeup or not.
        _filteredProcessContextSwitch++;

        // Get the process that made this thread become eligible to be switched in, if available.
        var readyingProcessImageName = sample.ReadyingProcess?.ImageName ?? "Unknown";
        // Was the new thread perhaps readied by a DPC?
        bool readyingThreadInDPC = false;
        if (sample.ReadyThreadEvent?.IsExecutingDeferredProcedureCall ?? false)
        {
          // If the readying thread is executing a deferred procedure it means that the thread was
          // not readied by a process. It was readied by a DPC call (doing work on behalf of an
          // interrupt) that has hijacked a process temporarily.
          readyingProcessImageName = "DPC";
          readyingThreadInDPC = true;
        }
        _filteredProcessReadyingProcesses.TryGetValue(readyingProcessImageName, out long count);
        _filteredProcessReadyingProcesses[readyingProcessImageName] = count + 1;

        if (switchOutImageName == "Idle")
        {
          // This context switch fulfiles the conditions of being categorized as an idle wakeup.
          // Note that more than one process can be included in the process filter but chrome.exe
          // is default.
          _filteredProcessIdleContextSwitch++;

          var switchInThreadId = contextSwitch.SwitchIn.ThreadId;

          // Stack of the thread switching in: the stack of the readied thread, which is both where
          // it resumes execution after the context switch, and where it was when its execution was
          // suspended on an earlier context switch. This represents where the thread was waiting.
          // WPA: New Thread Stack.
          var readiedThreadStackKey = contextSwitch.SwitchIn.Stack?.GetAnalyzerString();
          // Get the list of frames in the stack.
          var readiedThreadStackFrames = contextSwitch.SwitchIn.Stack?.Frames;

          // The stack of the thread, if any, which was readying (made eligible to run) the new thread.
          // WPA: The stack for the thread that readied the thread switching in.
          var readyingThreadStackKey = sample.ReadyThreadStack?.GetAnalyzerString();
          // Get the list of frames in the stack.
          var readyingThreadStackFrames = sample.ReadyThreadStack?.Frames;

          IdleWakeup iwakeup;
          if (!_idleWakeupsByThreadId.TryGetValue(switchInThreadId, out iwakeup))
          {
            // A new thread ID was found: update the context-switch counters and add the rest of the
            // information about the detected idle wakeup. These extra values are only stored once.
            iwakeup.ContextSwitchCount++;
            if (readyingThreadInDPC)
            {
              iwakeup.ContextSwitchDPCCount++;
            }
            iwakeup.ProcessId = contextSwitch.SwitchIn.Process.Id;
            iwakeup.ThreadName = contextSwitch.SwitchIn.Thread.Name;
            var commandLine = contextSwitch.SwitchIn.Process.CommandLine;
            iwakeup.ProcessName = switchInImageName;
            if (switchInImageName == "chrome.exe")
            {
              // For chrome.exe, add process type and subtype in addition to the process name. 
              iwakeup.ProcessType = GetChromeProcessType(commandLine);
            }
          }
          else
          {
            // Thread ID already exists: only update the context-switch counters for this key.
            iwakeup.ContextSwitchCount++;
            if (readyingThreadInDPC)
            {
              iwakeup.ContextSwitchDPCCount++;
            }
          }

          // Next (still using thread ID as key), also add two dictionaries for the new/readied
          // thread stack and the readying thread stack using unique strings from
          // GetAnalyzerString() as keys. For each key, store count and the a list of stack frames
          // as value.
          StackFrames stackFrames;
          if (iwakeup.ReadiedThreadStacks == null)
          {
            iwakeup.ReadiedThreadStacks = new Dictionary<string, StackFrames>();
          }
          if (readiedThreadStackKey != null && readiedThreadStackFrames != null)
          {
            iwakeup.ReadiedThreadStacks.TryGetValue(readiedThreadStackKey, out stackFrames);
            stackFrames.StackCount++;
            if (readyingThreadInDPC)
            {
              stackFrames.StackDPCCount++;
            }
            stackFrames.Stack = readiedThreadStackFrames;
            iwakeup.ReadiedThreadStacks[readiedThreadStackKey] = stackFrames;
          }

          if (iwakeup.ReadyingThreadStacks == null)
          {
            iwakeup.ReadyingThreadStacks = new Dictionary<string, StackFrames>();
          }
          if (readyingThreadStackKey != null && readyingThreadStackFrames != null)
          {
            iwakeup.ReadyingThreadStacks.TryGetValue(readyingThreadStackKey, out stackFrames);
            stackFrames.StackCount++;
            if (readyingThreadInDPC)
            {
              stackFrames.StackDPCCount++;
            }
            stackFrames.Stack = readyingThreadStackFrames;
            iwakeup.ReadyingThreadStacks[readyingThreadStackKey] = stackFrames;
          }

          // Store all aquired information about the idle wakeup in a dictionary with thread ID
          // as key and the IdleWakeup structure as value.
          _idleWakeupsByThreadId[switchInThreadId] = iwakeup;

          // Get the last C-State the processor went into when it was idle.
          // TODO(henrikand): perhaps exclude updating when in DPC.
          var prevCState = contextSwitch.PreviousCState;
          if (prevCState.HasValue)
          {
            _previousCStates.TryGetValue(prevCState.Value, out long cStateCount);
            cStateCount += 1;
            _previousCStates[prevCState.Value] = cStateCount;
          }

          // Finally, store the two stacks (readied/new and readying) once again but this time as
          // separate dictionaries (not as part of IdleWakeup) with thread ID as key. Instead, use
          // the unique strings from GetAnalyzerString() as keys and map count and list of stack
          // frames as value. This will give us the full/true distibution of callstacks since the
          // one stored with thread ID may contain copies of the same stack frames.
          if (readiedThreadStackKey != null && readiedThreadStackFrames != null)
          {
            _readiedThreadStacksByAnalyzerString.TryGetValue(readiedThreadStackKey, out stackFrames);
            stackFrames.StackCount++;
            if (readyingThreadInDPC)
            {
              stackFrames.StackDPCCount++;
            }
            stackFrames.Stack = readiedThreadStackFrames;
            _readiedThreadStacksByAnalyzerString[readiedThreadStackKey] = stackFrames;
          }

          if (readyingThreadStackKey != null && readyingThreadStackFrames != null)
          {
            _readyingThreadStacksByAnalyzerString.TryGetValue(readyingThreadStackKey, out stackFrames);
            stackFrames.StackCount++;
            stackFrames.Stack = readyingThreadStackFrames;
            _readyingThreadStacksByAnalyzerString[readyingThreadStackKey] = stackFrames;
          }

        }  // if (switchOutImageName == "Idle")
      }
    }

    public void WriteSummary()
    {
      // Add a high-level summary first.
      WriteHeader("High level summary:");

      var sep = _options.Tabbed ? "\t" : " : ";
      if (_wallTimeStart < _wallTimeEnd)
      {
        var durationMs = (_wallTimeEnd - _wallTimeStart) * 1000;
        Console.WriteLine("{0,-25}{1}{2:F}", "Duration (msec)", sep, durationMs);
      }
      var processFilter = ProcessFilterToString();
      Console.WriteLine("{0,-25}{1}{2}", "Process filter", sep, processFilter);
      Console.WriteLine("{0,-25}{1}{2}", "Context switches (On-CPU)", sep, _filteredProcessContextSwitch);
      Console.WriteLine("{0,-25}{1}{2}", "Idle wakeups", sep, _filteredProcessIdleContextSwitch);
      Console.WriteLine("{0,-25}{1}{2:F}", "Idle wakeups (%)",
        sep, 100 * (double)_filteredProcessIdleContextSwitch / _filteredProcessContextSwitch);
      Console.WriteLine();

      // Append a list of reading processes next.
      WriteHeader("Readying processes:");

      var composite = "{0,-25}{1}{2,6}";
      var sortedFilteredProcessReadyingProcesses =
        new List<KeyValuePair<string, long>>(_filteredProcessReadyingProcesses);
      sortedFilteredProcessReadyingProcesses.Sort((x, y) => y.Value.CompareTo(x.Value));
      foreach (var filteredProcessReadyingProcess in sortedFilteredProcessReadyingProcesses)
      {
        int length = filteredProcessReadyingProcess.Key.Length;
        Console.WriteLine(composite,
          filteredProcessReadyingProcess.Key[..Math.Min(length, 25)], sep,
          filteredProcessReadyingProcess.Value);
      }
      var totalReadyingProcesses = _filteredProcessReadyingProcesses.Sum(x => x.Value);
      Console.WriteLine(composite, "", sep, totalReadyingProcesses);
      Console.WriteLine();

      // Add a C-State distribution.
      WriteHeader($"Previous C-State (Idle -> {processFilter}) distribution with C-states as keys:");

      composite = "{0,7}{1}{2,7}{3}{4,9:F}";
      sep = _options.Tabbed ? "\t" : " ";
      string header = string.Format(composite,
        "C-State", sep,
        "Count", sep,
        "Count (%)");
      Console.WriteLine(header);
      WriteHeaderLine(header.Length + 1);

      var sortedPreviousCStatesList = _previousCStates.Keys.ToList();
      sortedPreviousCStatesList.Sort();
      foreach (var key in sortedPreviousCStatesList)
      {
        Console.WriteLine(composite,
          key, sep,
          _previousCStates[key], sep,
          100 * (double)_previousCStates[key] / _filteredProcessContextSwitch);
      }
      WriteHeaderLine(header.Length + 1);
      var totalPreviousCStatesCount = _previousCStates.Sum(x => x.Value);
      Console.WriteLine(composite,
        "", sep,
        totalPreviousCStatesCount, sep,
        "");
      Console.WriteLine();

      // Finally, show the main table summarizing the full Idle-wakeup distribution where thread
      // IDs for the filtered processes (default chrome.exe) act as keys.
      WriteHeader($"Idle-wakeup (Idle -> {processFilter}) distribution with thread IDs (TIDs) as keys:");
      Console.WriteLine("Context switches where the readying thread is executing a deferred procedure call (DPC) are included in Count.");
      Console.WriteLine();

      composite = "{0,6}{1}{2,6}{3}{4,-12}{5}{6,-12}{7}{8,-20}{9}{10,-55}{11}{12,6}{13}" +
                  "{14,9}{15}{16,6}{17}{18,7:F}{19}{20,7}{21}{22,14}{23}{24,15}";
      header = string.Format(composite,
        "TID", sep,
        "PID", sep,
        "Process", sep,
        "Chrome Type", sep,
        "Chrome Subtype", sep,
        "Thread Name", sep,
        "Count", sep,
        "Count/sec", sep,
        "DPC", sep,
        "DPC (%)", sep,
        "DPC/sec", sep,
        "Readied Stacks", sep,
        "Readying Stacks");
      Console.WriteLine(header);
      WriteHeaderLine(header.Length + 1);

      var durationInSec = _wallTimeEnd - _wallTimeStart;
      var sortedIdleWakeupsByThreadId = new List<KeyValuePair<int, IdleWakeup>>(_idleWakeupsByThreadId);
      sortedIdleWakeupsByThreadId.Sort((x, y)
          => y.Value.ContextSwitchCount.CompareTo(x.Value.ContextSwitchCount));
      foreach (var idleWakeup in sortedIdleWakeupsByThreadId)
      {
        var value = idleWakeup.Value;
        var dpcInPercent = 100 * value.ContextSwitchDPCCount / (double)value.ContextSwitchCount;
        Console.WriteLine(composite,
          idleWakeup.Key, sep,
          value.ProcessId, sep,
          value.ProcessName, sep,
          value.ProcessType.Type, sep,
          value.ProcessType.SubType, sep,
          value.ThreadName, sep,
          value.ContextSwitchCount, sep,
          Math.Round(value.ContextSwitchCount / durationInSec, MidpointRounding.AwayFromZero), sep,
          value.ContextSwitchDPCCount.ToString("#"), sep,
          dpcInPercent > 0 ? dpcInPercent : "", sep,
          Math.Round(value.ContextSwitchDPCCount / durationInSec, MidpointRounding.AwayFromZero).ToString("#"), sep,
          value.ReadiedThreadStacks.Count, sep,
          value.ReadyingThreadStacks.Count);
      }

      var totalContextSwitchCount = _idleWakeupsByThreadId.Sum(x => x.Value.ContextSwitchCount);
      var totalContextSwitchDPCCount = _idleWakeupsByThreadId.Sum(x => x.Value.ContextSwitchDPCCount);
      var totalReadyingThreadStacksCount = _idleWakeupsByThreadId.Sum(x => x.Value.ReadyingThreadStacks.Count);
      var totalReadiedThreadStacksCount = _idleWakeupsByThreadId.Sum(x => x.Value.ReadiedThreadStacks.Count);
      WriteHeaderLine(header.Length + 1);
      Console.WriteLine(composite,
        "", sep,
        "", sep,
        "", sep,
        "", sep,
        "", sep,
        "", sep,
        totalContextSwitchCount, sep,
        "", sep,
        totalContextSwitchDPCCount, sep,
        "", sep,
        "", sep,
        totalReadiedThreadStacksCount, sep,
        totalReadyingThreadStacksCount);
    }

    private ChromeProcessType GetChromeProcessType(string commandLine)
    {
      if (string.IsNullOrEmpty(commandLine))
      {
        return new ChromeProcessType("", "");
      }

      const string kProcessTypeParam = "--type=";
      const string kRendererProcessType = "renderer";
      const string kExtensionProcess = "extension";
      const string kExtensionParam = "--extension-process";
      const string kUtilityProcessType = "utility";
      const string kUtilitySubTypeParam = "--utility-sub-type=";
      const string kBrowserProcessType = "browser";
      const string kChrashpadProcess = "crashpad-handler";
      const string kChrashpadProcessShort = "crashpad";

      string type = kBrowserProcessType;
      string? subtype = null;

      var commandLineSplit = commandLine.Split();
      foreach (var commandLineArg in commandLineSplit)
      {
        if (commandLineArg.StartsWith(kProcessTypeParam))
        {
          type = commandLineArg[kProcessTypeParam.Length..];
          if (type == kChrashpadProcess)
          {
            type = kChrashpadProcessShort;
          }
          else if (type == kRendererProcessType && commandLine.Contains(kExtensionParam))
          {
            type = kExtensionProcess;
          }
          else if (type == kUtilityProcessType)
          {
            var utilitySubType = commandLineSplit.First(s => s.StartsWith(kUtilitySubTypeParam));
            if (utilitySubType != null)
            {
              // Example: 'video_capture.mojom.VideoCaptureService'.
              subtype = utilitySubType[kUtilitySubTypeParam.Length..];
              // Return only the last 'VideoCaptureService' part of this string.
              var subs = subtype.Split('.');
              subtype = subs[subs.Length - 1];
              break;
            }
          }
        }
      }

      return new ChromeProcessType(type, subtype);
    }

    private void WriteHeader(string header)
    {
      Console.ForegroundColor = ConsoleColor.Yellow;
      Console.WriteLine(header);
      Console.WriteLine();
      Console.ForegroundColor = ConsoleColor.White;
    }

    private void WriteHeaderLine(int lenght)
    {
      StringBuilder sb = new StringBuilder();
      if (!_options.Tabbed)
      {
        for (int i = 0; i < lenght; i++)
        {
          sb.Append("-");
        }
        Console.WriteLine(sb.ToString());
      }
    }

    private void WriteVerbose(string message)
    {
      if (!_options.Verbose)
        return;
      Console.ForegroundColor = ConsoleColor.Green;
      Console.WriteLine(message);
      Console.ForegroundColor = ConsoleColor.White;
    }

    private string ProcessFilterToString()
    {
      StringBuilder sb = new StringBuilder();
      if (_options.ProcessFilterSet == null)
        return "*";
      foreach (var item in _options.ProcessFilterSet)
      {
        sb.Append(item);
        sb.Append(' ');
      }
      return sb.ToString().TrimEnd();
    }

    private readonly Options _options;

    private long _filteredProcessContextSwitch;

    private long _filteredProcessIdleContextSwitch;

    private decimal _wallTimeStart = decimal.MaxValue;
    private decimal _wallTimeEnd = 0;

    private Dictionary<int, IdleWakeup> _idleWakeupsByThreadId = new();

    private Dictionary<string, long> _filteredProcessReadyingProcesses = new();

    private Dictionary<int, long> _previousCStates = new();

    private Dictionary<string, StackFrames> _readyingThreadStacksByAnalyzerString = new();

    private Dictionary<string, StackFrames> _readiedThreadStacksByAnalyzerString = new();
  }
}

/* ----- snippets
 
 const int threadId = 13972;

      Console.WriteLine($"New Thread Stacks (TID={threadId})");
      Console.WriteLine();

      long sum = 0;
      long sumd = 0;
      var readiedThreadStacks = _idleWakeupsByThreadId[threadId].ReadiedThreadStacks;
      foreach (var readiedThreadStack in readiedThreadStacks)
      {
        // if (readiedThreadStack.Value.StackDPCCount == 0)
        //  continue;
        // Console.WriteLine(newThreadStack.Key);

        // Console.WriteLine("iwakeup:");
                // foreach (var entry in readiedThreadStack.Value.Stack)
                // {
                // var stackFrame = entry.GetAnalyzerString();
                // Console.WriteLine("        {0}", stackFrame);
                // }

        Console.WriteLine("{0} {1}", readiedThreadStack.Value.StackCount, readiedThreadStack.Value.StackDPCCount);
        // Console.WriteLine("{0}", readiedThreadStack.Value.StackCount);
        sum += readiedThreadStack.Value.StackCount;
        sumd += readiedThreadStack.Value.StackDPCCount;
      }
      Console.WriteLine("Total: {0} {1}", sum, sumd);

      Console.WriteLine();
      Console.WriteLine($"Ready Thread Stacks (TID={threadId})");
      Console.WriteLine();

      sum = 0;
      sumd = 0;
      var readyingThreadStacks = _idleWakeupsByThreadId[threadId].ReadyingThreadStacks;
      foreach (var readyingThreadStack in readyingThreadStacks)
      {
        // if (readyingThreadStack.Value.StackDPCCount == 0)
        //  continue;
        // Console.WriteLine(readyThreadStack.Key);
        // Console.WriteLine("iwakeup:");
                //foreach (var entry in readyingThreadStack.Value.Stack)
                //{
                //  var stackFrame = entry.GetAnalyzerString();
                //  Console.WriteLine("        {0}", stackFrame);
                //}
        Console.WriteLine("{0} {1}", readyingThreadStack.Value.StackCount, readyingThreadStack.Value.StackDPCCount);
        // Console.WriteLine("{0}", readyingThreadStack.Value.StackCount);
        sum += readyingThreadStack.Value.StackCount;
        sumd += readyingThreadStack.Value.StackDPCCount;
      }
      Console.WriteLine("Total: {0} {1}", sum, sumd);

      const int maxPrinted = 10;

      var sortedReadyThreadStacksByAnalyzerString =
          new List<KeyValuePair<string, StackFrames>>(_readyThreadStacksByAnalyzerString);
      sortedReadyThreadStacksByAnalyzerString.Sort((x, y) => y.Value.Count.CompareTo(x.Value.Count));
      foreach (KeyValuePair<string, StackFrames> kvp in sortedReadyThreadStacksByAnalyzerString.Take(maxPrinted))
      {
        Console.WriteLine("iwakeup:");
        foreach (var entry in kvp.Value.Stack)
        {
          try
          {
            var stackFrame = entry.GetAnalyzerString();
            Console.WriteLine("        {0}", stackFrame);
          }
          catch (Exception ex)
          {
            // Console.WriteLine(ex.ToString());
          }
        }
        Console.WriteLine("        {0}", kvp.Value.Count);
      }

 https://paste.googleplex.com/4931316148600832
var sortedNewThreadStacksByAnalyzerString =
    new List<KeyValuePair<string, StackFrames>>(_newThreadStacksByAnalyzerString);
sortedNewThreadStacksByAnalyzerString.Sort((x, y) => y.Value.Count.CompareTo(x.Value.Count));
foreach (KeyValuePair<string, StackFrames> kvp in sortedNewThreadStacksByAnalyzerString.Take(maxPrinted))
{
  Console.WriteLine("iwakeup:");
  foreach (var entry in kvp.Value.Stack)
  {
    var stackFrame = entry.GetAnalyzerString();
    Console.WriteLine("        {0}", stackFrame);
  }
  Console.WriteLine("        {0}", kvp.Value.Count);
}
Console.WriteLine();
Console.WriteLine(_newThreadStacksByAnalyzerString.Count);
*/
