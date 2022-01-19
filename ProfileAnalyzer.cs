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

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Google.Protobuf;
using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Cpu;
using Microsoft.Windows.EventTracing.Symbols;
using pb = Perftools.Profiles;

namespace IdleWakeups
{
  internal class ProfileAnalyzer
  {
    public struct Options
    {
      public string EtlFileName { get; set; }
      public bool IncludeProcessIds { get; set; }
      public bool IncludeProcessAndThreadIds { get; set; }
      public bool SplitChromeProcesses { get; set; }
      public decimal TimeStart { get; set; }
      public decimal TimeEnd { get; set; }
      public HashSet<string> ProcessFilterSet { get; set; }
      public bool Tabbed { get; set; }
      public bool Verbose { get; set; }
    }

    public ProfileAnalyzer(Options options)
    {
      _options = options;

      // TODO(henrika): add to options
      const string stripSourceFileNamePrefix = @"^c:/b/s/w/ir/cache/builder/";
      _stripSourceFileNamePrefixRegex = new Regex(stripSourceFileNamePrefix,
                                                  RegexOptions.Compiled | RegexOptions.IgnoreCase);

      _strings = new Dictionary<string, long>();
      _strings.Add("", 0);
      _nextStringId = 1;
      _profile.StringTable.Add("");

      _locations = new Dictionary<Location, ulong>();
      _nextLocationId = 1;

      _functions = new Dictionary<Function, ulong>();
      _nextFunctionId = 1;

      // When a thread is off-CPU sleeping, it is eventually woken up. This is performed by
      // another thread, the waker thread.

      // Counts all callstacks for woken threads related to idlewakeups where a context switch
      // between an (old) idle thread and (new) thread in e.g. Chrome has taken place.
      var iWakeupCountValueType = new pb.ValueType();
      iWakeupCountValueType.Type = GetStringId("woken_all");
      iWakeupCountValueType.Unit = GetStringId("count");
      _profile.SampleType.Add(iWakeupCountValueType);

      // Counts all woken callstacks where the waker thread was not doing DPC.
      iWakeupCountValueType = new pb.ValueType();
      iWakeupCountValueType.Type = GetStringId("woken_no_dpc");
      iWakeupCountValueType.Unit = GetStringId("count");
      _profile.SampleType.Add(iWakeupCountValueType);

      // Counts all woken callstacks where the waker thread was doing DPC.
      iWakeupCountValueType = new pb.ValueType();
      iWakeupCountValueType.Type = GetStringId("woken_dpc");
      iWakeupCountValueType.Unit = GetStringId("count");
      _profile.SampleType.Add(iWakeupCountValueType);

      // Counts all callstacks for waker threads related to idlewakeups where a context switch
      // between an (old) idle thread and (new) thread in e.g. Chrome has taken place. These
      // callstacks comes from the readying thread that made the new thread eligible to run.
      iWakeupCountValueType = new pb.ValueType();
      iWakeupCountValueType.Type = GetStringId("waker_all");
      iWakeupCountValueType.Unit = GetStringId("count");
      _profile.SampleType.Add(iWakeupCountValueType);

      // Counts all waker callstacks where the waker thread was not doing DPC.
      iWakeupCountValueType = new pb.ValueType();
      iWakeupCountValueType.Type = GetStringId("waker_no_dpc");
      iWakeupCountValueType.Unit = GetStringId("count");
      _profile.SampleType.Add(iWakeupCountValueType);

      // Counts all waker callstacks where the waker thread was not doing DPC.
      iWakeupCountValueType = new pb.ValueType();
      iWakeupCountValueType.Type = GetStringId("waker_dpc");
      iWakeupCountValueType.Unit = GetStringId("count");
      _profile.SampleType.Add(iWakeupCountValueType);
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
        var wakerProcessImageName = sample.ReadyingProcess?.ImageName ?? "Unknown";
        // Was the waker thread executing a DPC?
        bool wakerThreadInDPC = false;
        if (sample.ReadyThreadEvent?.IsExecutingDeferredProcedureCall ?? false)
        {
          // If the waker thread is executing a deferred procedure it means that the woken thread
          // was not woken by a process. It was woken by a DPC call (doing work on behalf of an
          // interrupt) that has hijacked a process temporarily.
          wakerProcessImageName = "DPC";
          wakerThreadInDPC = true;
        }
        _filteredProcessWakerProcesses.TryGetValue(wakerProcessImageName, out long count);
        _filteredProcessWakerProcesses[wakerProcessImageName] = count + 1;

        if (switchOutImageName == "Idle")
        {
          // This context switch fulfiles the conditions of being categorized as an idle wakeup.
          // Note that more than one process can be included in the process filter but chrome.exe
          // is default.
          _filteredProcessIdleContextSwitch++;

          var switchInThreadId = contextSwitch.SwitchIn.ThreadId;

          // Stack of the thread switching in: the stack of the woken thread, which is both where
          // it resumes execution after the context switch, and where it was when its execution was
          // suspended on an earlier context switch. This represents where the thread was waiting.
          // WPA: New Thread Stack.
          var wokenThreadStackKey = contextSwitch.SwitchIn.Stack?.GetAnalyzerString();
          // Get the list of frames in the stack.
          var wokenThreadStackFrames = contextSwitch.SwitchIn.Stack?.Frames;

          // The stack of the waker thread, if any, which was waking up the new thread.
          // WPA: The stack for the thread that readied the thread switching in.
          var wakerThreadStackKey = sample.ReadyThreadStack?.GetAnalyzerString();
          // Get the list of frames in the stack.
          var wakerThreadStackFrames = sample.ReadyThreadStack?.Frames;

          IdleWakeup iwakeup;
          if (!_idleWakeupsByThreadId.TryGetValue(switchInThreadId, out iwakeup))
          {
            // A new thread ID was found: update the context-switch counters and add the rest of the
            // information about the detected idle wakeup. These extra values are only stored once.
            iwakeup.ContextSwitchCount++;
            if (wakerThreadInDPC)
            {
              iwakeup.ContextSwitchDPCCount++;
            }
            iwakeup.ProcessId = contextSwitch.SwitchIn.Process.Id;
            iwakeup.ThreadName = contextSwitch.SwitchIn.Thread.Name;
            iwakeup.ThreadStartAddress = contextSwitch.SwitchIn.Thread.StartAddress;
            var commandLine = contextSwitch.SwitchIn.Process.CommandLine;
            iwakeup.ProcessName = switchInImageName;
            iwakeup.WakerProcessName = wakerProcessImageName;
            iwakeup.ObjectAddress = contextSwitch.SwitchIn.Process.ObjectAddress;
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
            if (wakerThreadInDPC)
            {
              iwakeup.ContextSwitchDPCCount++;
            }
          }

          // Next (still using thread ID as key), also add two dictionaries for the woken/readied
          // thread stack and the waker/readying thread stack using unique strings from
          // GetAnalyzerString() as keys. For each key, store count and the a list of stack frames
          // as value.
          StackFrames stackFrames;
          if (iwakeup.WokenThreadStacks == null)
          {
            iwakeup.WokenThreadStacks = new Dictionary<string, StackFrames>();
          }
          if (wokenThreadStackKey != null && wokenThreadStackFrames != null)
          {
            iwakeup.WokenThreadStacks.TryGetValue(wokenThreadStackKey, out stackFrames);
            stackFrames.StackCount++;
            if (wakerThreadInDPC)
            {
              stackFrames.StackDPCCount++;
            }
            stackFrames.Stack = wokenThreadStackFrames;
            iwakeup.WokenThreadStacks[wokenThreadStackKey] = stackFrames;
          }

          if (iwakeup.WakerThreadStacks == null)
          {
            iwakeup.WakerThreadStacks = new Dictionary<string, StackFrames>();
          }
          if (wakerThreadStackKey != null && wakerThreadStackFrames != null)
          {
            iwakeup.WakerThreadStacks.TryGetValue(wakerThreadStackKey, out stackFrames);
            stackFrames.StackCount++;
            if (wakerThreadInDPC)
            {
              stackFrames.StackDPCCount++;
            }
            stackFrames.Stack = wakerThreadStackFrames;
            iwakeup.WakerThreadStacks[wakerThreadStackKey] = stackFrames;
          }

          // Store all aquired information about the idle wakeup in a dictionary with thread ID
          // as key and the IdleWakeup structure as value.
          _idleWakeupsByThreadId[switchInThreadId] = iwakeup;

          // Get the last C-State the processor went into when it was idle.
          var prevCState = contextSwitch.PreviousCState;
          if (prevCState.HasValue)
          {
            _previousCStates.TryGetValue(prevCState.Value, out long cStateCount);
            cStateCount += 1;
            _previousCStates[prevCState.Value] = cStateCount;
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

      // Append a list of waker/reading processes.
      WriteHeader("Waker processes:");

      var composite = "{0,-25}{1}{2,6}";
      var sortedFilteredProcessWakerProcesses =
        new List<KeyValuePair<string, long>>(_filteredProcessWakerProcesses);
      sortedFilteredProcessWakerProcesses.Sort((x, y) => y.Value.CompareTo(x.Value));
      foreach (var filteredProcessWakerProcess in sortedFilteredProcessWakerProcesses)
      {
        int length = filteredProcessWakerProcess.Key.Length;
        Console.WriteLine(composite,
          filteredProcessWakerProcess.Key[..Math.Min(length, 25)], sep,
          filteredProcessWakerProcess.Value);
      }
      var totalWakerProcesses = _filteredProcessWakerProcesses.Sum(x => x.Value);
      Console.WriteLine(composite, "", sep, totalWakerProcesses);
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
      Console.WriteLine("Context switches where the waker thread is executing a deferred procedure call (DPC) are included in Count.");
      Console.WriteLine();

      composite = "{0,6}{1}{2,6}{3}{4,-12}{5}{6,-12}{7}{8,-20}{9}{10,-55}{11}{12,6}{13}" +
                  "{14,9}{15}{16,6}{17}{18,7:F}{19}{20,7}{21}{22,12}{23}{24,12}";
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
        "Woken Stacks", sep,
        "Waker Stacks");
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
        string dpcInPercentAsString = "";
        if (dpcInPercent > 0)
        {
          dpcInPercentAsString = dpcInPercent.ToString("0.#0");
        }
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
          dpcInPercentAsString, sep,
          Math.Round(value.ContextSwitchDPCCount / durationInSec, MidpointRounding.AwayFromZero).ToString("#"), sep,
          value.WokenThreadStacks.Count, sep,
          value.WakerThreadStacks.Count);
      }

      var totalContextSwitchCount = _idleWakeupsByThreadId.Sum(x => x.Value.ContextSwitchCount);
      var totalContextSwitchDPCCount = _idleWakeupsByThreadId.Sum(x => x.Value.ContextSwitchDPCCount);
      var totalWakerThreadStacksCount = _idleWakeupsByThreadId.Sum(x => x.Value.WakerThreadStacks.Count);
      var totalWokenThreadStacksCount = _idleWakeupsByThreadId.Sum(x => x.Value.WokenThreadStacks.Count);
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
        totalWokenThreadStacksCount, sep,
        totalWakerThreadStacksCount);
    }

    public long WritePprof(string outputFileName)
    {
      if (_wallTimeStart < _wallTimeEnd)
      {
        var durationMs = (_wallTimeEnd - _wallTimeStart) * 1000;
        var etlFileName = _options.EtlFileName.TrimStart(' ', '.', '\\');
        _profile.Comment.Add(GetStringId($"ETL file: {etlFileName}"));
        _profile.Comment.Add(GetStringId($"Duration (msec): {durationMs:F}"));
        var processFilter = ProcessFilterToString();
        _profile.Comment.Add(GetStringId($"Process filter: {processFilter}"));
        _profile.Comment.Add(GetStringId($"Context switches (On-CPU): {_filteredProcessContextSwitch}"));
        _profile.Comment.Add(GetStringId($"Idle wakeups: {_filteredProcessIdleContextSwitch}"));
        var IdleWakeupsInPercent = 100 * (double)_filteredProcessIdleContextSwitch / _filteredProcessContextSwitch;
        _profile.Comment.Add(GetStringId($"Idle wakeups (%): {IdleWakeupsInPercent:F}"));
      }
      else
      {
        _profile.Comment.Add(GetStringId("No samples exported"));
      }

      foreach (var tidAndIdleWakeup in _idleWakeupsByThreadId)
      {
        AddSamplesToProfile(ThreadStackTypes.Woken, tidAndIdleWakeup);
        AddSamplesToProfile(ThreadStackTypes.Waker, tidAndIdleWakeup);
      }

      _profile.Comment.Add(
        GetStringId($"Exported by https://github.com/google/IdleWakeups from {Path.GetFileName(outputFileName)}"));

      using (FileStream output = File.Create(outputFileName))
      {
        using (GZipStream gzip = new GZipStream(output, CompressionMode.Compress))
        {
          using (CodedOutputStream serialized = new CodedOutputStream(gzip))
          {
            // Write the profile data to the given Gzip coded output stream.
            _profile.WriteTo(serialized);
            return output.Length;
          }
        }
      }
    }

    private void AddSamplesToProfile(ThreadStackTypes type, KeyValuePair<int, IdleWakeup> tidAndIdleWakeup)
    {
      var threadId = tidAndIdleWakeup.Key;
      var idleWakeup = tidAndIdleWakeup.Value;

      var processId = idleWakeup.ProcessId;
      var threadStartAddress = idleWakeup.ThreadStartAddress;
      var objectAddress = idleWakeup.ObjectAddress;

      // Write callstacks related to all woken or waker threads depending on `type`.
      Dictionary<string, StackFrames> threadStacks =
        type == ThreadStackTypes.Woken ? idleWakeup.WokenThreadStacks : idleWakeup.WakerThreadStacks;
      foreach (var stack in threadStacks.Values)
      {
        var stackFrames = stack.Stack;
        if (stackFrames.Count == 0)
        {
          continue;
        }

        var sampleProto = new pb.Sample();
        if (type == ThreadStackTypes.Woken)
        {
          sampleProto.Value.Add(stack.StackCount);
          sampleProto.Value.Add(stack.StackCount - stack.StackDPCCount);
          sampleProto.Value.Add(stack.StackDPCCount);
          sampleProto.Value.Add(0);
          sampleProto.Value.Add(0);
          sampleProto.Value.Add(0);
        }
        else
        {
          sampleProto.Value.Add(0);
          sampleProto.Value.Add(0);
          sampleProto.Value.Add(0);
          sampleProto.Value.Add(stack.StackCount);
          sampleProto.Value.Add(stack.StackCount - stack.StackDPCCount);
          sampleProto.Value.Add(stack.StackDPCCount);
        }

        foreach (var stackFrame in stackFrames)
        {
          if (stackFrame.HasValue && stackFrame.Symbol != null)
          {
            // Add valid stack frame to the proto buffer.
            sampleProto.LocationId.Add(GetLocationId(stackFrame.Symbol));
          }
          else
          {
            // Current stack frame was invalid, mark it as "unknown" to maintain a correct depth
            // of the total stack.
            string imageName = stackFrame.Image?.FileName ?? "<unknown>";
            string functionLabel = "<unknown>";
            sampleProto.LocationId.Add(
              GetPseudoLocationId(processId, imageName, null, functionLabel));
          }
        }

        if (type == ThreadStackTypes.Woken ||
            type == ThreadStackTypes.Waker && idleWakeup.WakerProcessName == "chrome.exe")
        {
          // Add thread name and possibly also thread id as label.
          string processName = idleWakeup.ProcessName;
          string threadLabel = idleWakeup.ThreadName;
          if (String.IsNullOrEmpty(threadLabel))
            threadLabel = "anonymous";
          if (_options.IncludeProcessAndThreadIds)
          {
            threadLabel = String.Format("{0} ({1})", threadLabel, threadId);
          }
          sampleProto.LocationId.Add(
            GetPseudoLocationId(processId, processName, threadStartAddress, threadLabel));

          // Add process name, type and possibly id as label depending on current options.
          string processLabel = processName;
          if (_options.SplitChromeProcesses && processName == "chrome.exe")
          {
            const string kUtilityProcessType = "utility";
            var chromeProcessType = idleWakeup.ProcessType;
            if (chromeProcessType.Type == kUtilityProcessType)
            {
              processLabel = processLabel + $" ({chromeProcessType.SubType})";
            }
            else
            {
              processLabel = processLabel + $" ({chromeProcessType.Type})";
            }
          }
          if (_options.IncludeProcessIds || _options.IncludeProcessAndThreadIds)
          {
            processLabel = processLabel + $" ({processId})";
          }
          sampleProto.LocationId.Add(
            GetPseudoLocationId(processId, processName, objectAddress, processLabel));
        }

        _profile.Sample.Add(sampleProto);
      }
    }
    private enum ThreadStackTypes
    {
      Woken,
      Waker
    }

    private struct IdleWakeup
    {
      public long ContextSwitchCount { get; set; }
      public long ContextSwitchDPCCount { get; set; }
      public int ProcessId { get; set; }
      public string ProcessName { get; set; }
      public string WakerProcessName { get; set; }
      public Address ObjectAddress { get; set; }
      public Address ThreadStartAddress { get; set; }
      public ChromeProcessType ProcessType { get; set; }
      public string ThreadName { get; set; }
      public Dictionary<string, StackFrames> WakerThreadStacks { get; set; }
      public Dictionary<string, StackFrames> WokenThreadStacks { get; set; }
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

    readonly struct Location
    {
      public Location(int processId, string imagePath, Address? functionAddress, string functionName)
      {
        ProcessId = processId;
        ImagePath = imagePath;
        FunctionAddress = functionAddress;
        FunctionName = functionName;
      }
      int ProcessId { get; }
      string ImagePath { get; }
      Address? FunctionAddress { get; }
      string FunctionName { get; }

      public override bool Equals(object? other)
      {
        return other is Location location &&
               ProcessId == location.ProcessId &&
               ImagePath == location.ImagePath &&
               EqualityComparer<Address?>.Default.Equals(FunctionAddress, location.FunctionAddress) &&
               FunctionName == location.FunctionName;
      }

      public override int GetHashCode()
      {
        return HashCode.Combine(ProcessId, ImagePath, FunctionAddress, FunctionName);
      }
    }

    readonly struct Function
    {
      public Function(string imageName, string functionName)
      {
        ImageName = imageName;
        FunctionName = functionName;
      }
      string ImageName { get; }
      string FunctionName { get; }

      public override bool Equals(object? other)
      {
        return other is Function function &&
               ImageName == function.ImageName &&
               FunctionName == function.FunctionName;
      }

      public override int GetHashCode()
      {
        return HashCode.Combine(ImageName, FunctionName);
      }

      public override string ToString()
      {
        return String.Format("{0}!{1}", ImageName, FunctionName);
      }
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

    private void AddLocationsToSample(pb.Sample sampleProto)
    {

    }


    // string_table: All strings in the profile are represented as indices into this repeating
    // field. The first string is empty, so index == 0 always represents the empty string.
    private long GetStringId(string str)
    {
      long stringId;
      if (!_strings.TryGetValue(str, out stringId))
      {
        stringId = _nextStringId++;
        _strings.Add(str, stringId);
        _profile.StringTable.Add(str);
      }
      return stringId;
    }

    // Location: A unique place in the program, commonly mapped to a single instruction address.
    // It has a unique nonzero id, to be referenced from the samples. It contains source information
    // in the form of lines, and a mapping id that points to a binary.
    private ulong GetLocationId(IStackSymbol stackSymbol)
    {
      if (stackSymbol.Image == null)
      {
        // TODO(henrika): resolves some compiler warnings related to nullability of reference
        // types but I have not seen any error messages printed out so far. Hence, not sure if
        // more work is needed here or not.
        Console.Error.WriteLine("Invalid stack symbol image");
        return 0;
      }

      var processId = stackSymbol.Image.ProcessId;
      var imagePath = stackSymbol.Image.Path;
      var functionAddress = stackSymbol.AddressRange.BaseAddress;
      var functionName = stackSymbol.FunctionName;

      var location = new Location(processId, imagePath, functionAddress, functionName);

      ulong locationId;
      if (!_locations.TryGetValue(location, out locationId))
      {
        locationId = _nextLocationId++;
        _locations.Add(location, locationId);

        var locationProto = new pb.Location();
        locationProto.Id = locationId;

        pb.Line line;

        /* TODO(henrika)
        if (options.includeInlinedFunctions && stackSymbol.InlinedFunctionNames != null)
        {
          foreach (var inlineFunctionName in stackSymbol.InlinedFunctionNames)
          {
            line = new pb.Line();
            line.FunctionId = GetFunctionId(imageName, inlineFunctionName);
            locationProto.Line.Add(line);
          }
        }
        */

        var imageName = stackSymbol.Image.FileName;
        var sourceFileName = stackSymbol.SourceFileName;

        line = new pb.Line();
        line.FunctionId = GetFunctionId(imageName, functionName, sourceFileName);
        line.Line_ = stackSymbol.SourceLineNumber;
        locationProto.Line.Add(line);
        _profile.Location.Add(locationProto);
      }
      return locationId;
    }

    ulong GetPseudoLocationId(int processId, string imageName, Address? address, string label)
    {
      var location = new Location(processId, imageName, address, label);
      ulong locationId;
      if (!_locations.TryGetValue(location, out locationId))
      {
        locationId = _nextLocationId++;
        _locations.Add(location, locationId);

        var locationProto = new pb.Location();
        locationProto.Id = locationId;

        var line = new pb.Line();
        line.FunctionId = GetFunctionId(imageName, label);
        locationProto.Line.Add(line);

        _profile.Location.Add(locationProto);
      }
      return locationId;
    }

    // Function: A program function as defined in the program source. It has a unique nonzero id,
    // referenced from the location lines. It contains a human-readable name for the function
    // (eg a C++ demangled name), a system name (eg a C++ mangled name), the name of the
    // corresponding source file, and other function attributes.
    private ulong GetFunctionId(string imageName, string functionName, string sourceFileName = null!)
    {
      ulong functionId;
      var function = new Function(imageName, functionName);
      if (!_functions.TryGetValue(function, out functionId))
      {
        var functionProto = new pb.Function();
        functionProto.Id = _nextFunctionId++;
        functionProto.Name = GetStringId(functionName ?? function.ToString());
        functionProto.SystemName = GetStringId(function.ToString());
        if (sourceFileName == null)
        {
          sourceFileName = imageName;
        }
        else
        {
          // Example: C:\b\s\w\ir\cache\builder\src\base\threading\thread.cc =>
          //          src/base/threading/thread.cc
          sourceFileName = sourceFileName.Replace('\\', '/');
          sourceFileName = _stripSourceFileNamePrefixRegex.Replace(sourceFileName, "");
        }
        functionProto.Filename = GetStringId(sourceFileName);

        functionId = functionProto.Id;
        _functions.Add(function, functionId);
        _profile.Function.Add(functionProto);
      }
      return functionId;
    }

    readonly Options _options;

    long _filteredProcessContextSwitch;

    long _filteredProcessIdleContextSwitch;

    decimal _wallTimeStart = decimal.MaxValue;
    decimal _wallTimeEnd = 0;

    Dictionary<string, long> _strings;
    long _nextStringId;

    Dictionary<Location, ulong> _locations;
    ulong _nextLocationId;

    Dictionary<Function, ulong> _functions;
    ulong _nextFunctionId;

    Regex _stripSourceFileNamePrefixRegex;

    Dictionary<int, IdleWakeup> _idleWakeupsByThreadId = new Dictionary<int, IdleWakeup>();

    Dictionary<string, long> _filteredProcessWakerProcesses = new Dictionary<string, long>();

    Dictionary<int, long> _previousCStates = new Dictionary<int, long>();

    pb.Profile _profile = new pb.Profile();
  }
}
