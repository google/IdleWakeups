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

using Google.Protobuf;

using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Cpu;
using Microsoft.Windows.EventTracing.Symbols;

using pb = Perftools.Profiles;

using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

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
        // return (ProcessId, ImagePath, FunctionAddress, FunctionName).GetHashCode();
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

      var iWakeupCountValueType = new pb.ValueType();
      iWakeupCountValueType.Type = GetStringId("readied stacks");
      iWakeupCountValueType.Unit = GetStringId("count");
      _profile.SampleType.Add(iWakeupCountValueType);

      iWakeupCountValueType = new pb.ValueType();
      iWakeupCountValueType.Type = GetStringId("readying stacks");
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
      if (_options.ProcessFilterSet is null ||
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
          if (iwakeup.ReadiedThreadStacks is null)
          {
            iwakeup.ReadiedThreadStacks = new Dictionary<string, StackFrames>();
          }
          if (readiedThreadStackKey is not null && readiedThreadStackFrames is not null)
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

          if (iwakeup.ReadyingThreadStacks is null)
          {
            iwakeup.ReadyingThreadStacks = new Dictionary<string, StackFrames>();
          }
          if (readyingThreadStackKey is not null && readyingThreadStackFrames is not null)
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
          if (readiedThreadStackKey is not null && readiedThreadStackFrames is not null)
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

          if (readyingThreadStackKey is not null && readyingThreadStackFrames is not null)
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

    /*
      profile.Comment.Add(GetStringId($"Converted by EtwToPprof from {Path.GetFileName(options.etlFileName)}"));
      if (wallTimeStart < wallTimeEnd)
      {
        decimal wallTimeMs = (wallTimeEnd - wallTimeStart) * 1000;
        profile.Comment.Add(GetStringId($"Wall time {wallTimeMs:F} ms"));
        profile.Comment.Add(GetStringId($"CPU time {totalCpuTime:F} ms ({totalCpuTime / wallTimeMs:P})"));

        var sortedProcesses = processCpuTimes.Keys.ToList();
        sortedProcesses.Sort((a, b) => -processCpuTimes[a].CompareTo(processCpuTimes[b]));

        foreach (var processLabel in sortedProcesses)
        {
          decimal processCpuTime = processCpuTimes[processLabel];
          profile.Comment.Add(GetStringId($"  {processLabel} {processCpuTime:F} ms ({processCpuTime / wallTimeMs:P})"));

          var threadCpuTimes = processThreadCpuTimes[processLabel];

          var sortedThreads = threadCpuTimes.Keys.ToList();
          sortedThreads.Sort((a, b) => -threadCpuTimes[a].CompareTo(threadCpuTimes[b]));

          foreach (var threadLabel in sortedThreads)
          {
            var threadCpuTime = threadCpuTimes[threadLabel];
            profile.Comment.Add(GetStringId($"    {threadLabel} {threadCpuTime:F} ms ({threadCpuTime / wallTimeMs:P})"));
          }
        }
      }
      else
      {
        profile.Comment.Add(GetStringId("No samples exported"));
      }
      using (FileStream output = File.Create(outputFileName))
      {
        using (GZipStream gzip = new GZipStream(output, CompressionMode.Compress))
        {
          using (CodedOutputStream serialized = new CodedOutputStream(gzip))
          {
            profile.WriteTo(serialized);
            return output.Length;
          }
        }
      }
     */

    public long WritePprof(string outputFileName)
    {
      if (_wallTimeStart < _wallTimeEnd)
      {
        var durationMs = (_wallTimeEnd - _wallTimeStart) * 1000;
        _profile.Comment.Add(GetStringId($"Duration (msec): {durationMs:F}"));
      }
      else
      {
        _profile.Comment.Add(GetStringId("No samples exported"));
      }
      const int numStacks = 10;
      var sortedReadiedThreadStacksByAnalyzerString =
           new List<KeyValuePair<string, StackFrames>>(_readiedThreadStacksByAnalyzerString);
      sortedReadiedThreadStacksByAnalyzerString.Sort((x, y) => y.Value.StackCount.CompareTo(x.Value.StackCount));
      /*
      foreach (KeyValuePair<string, StackFrames> kvp in sortedReadiedThreadStacksByAnalyzerString.Take(numStacks))
      {
        Console.WriteLine("iwakeup:");
        foreach (var entry in kvp.Value.Stack)
        {
          var stackFrame = entry.GetAnalyzerString();
          Console.WriteLine("        {0}", stackFrame);
        }
        Console.WriteLine("        {0}", kvp.Value.StackCount);
      }*/

      foreach (KeyValuePair<string, StackFrames> kvp in sortedReadiedThreadStacksByAnalyzerString.Take(numStacks))
      {
        var sampleProto = new pb.Sample();
        sampleProto.Value.Add(kvp.Value.StackCount);
        sampleProto.Value.Add(0);
        var stackFrames = kvp.Value.Stack;

        if (stackFrames.Count == 0)
        {
          continue;
        }

        foreach (var stackFrame in stackFrames)
        {
          if (stackFrame.HasValue && stackFrame.Symbol is not null)
          {
            sampleProto.LocationId.Add(GetLocationId(stackFrame.Symbol));
          }
          else
          {
            // TODO(henrika): improve...
            Console.Error.WriteLine("Invalid stackFrame");
          }
        }

        _profile.Sample.Add(sampleProto);
      }

      Console.WriteLine();

      var sortedReadyingThreadStacksByAnalyzerString =
          new List<KeyValuePair<string, StackFrames>>(_readyingThreadStacksByAnalyzerString);
      sortedReadyingThreadStacksByAnalyzerString.Sort((x, y) => y.Value.StackCount.CompareTo(x.Value.StackCount));
      /*
      foreach (KeyValuePair<string, StackFrames> kvp in sortedReadyingThreadStacksByAnalyzerString.Take(numStacks))
      {
        Console.WriteLine("iwakeup:");
        foreach (var entry in kvp.Value.Stack)
        {
          var stackFrame = entry.GetAnalyzerString();
          Console.WriteLine("        {0}", stackFrame);
        }
        Console.WriteLine("        {0}", kvp.Value.StackCount);
      }*/

      foreach (KeyValuePair<string, StackFrames> kvp in sortedReadyingThreadStacksByAnalyzerString.Take(numStacks))
      {
        var sampleProto = new pb.Sample();
        sampleProto.Value.Add(0);
        sampleProto.Value.Add(kvp.Value.StackCount);
        var stackFrames = kvp.Value.Stack;

        if (stackFrames.Count == 0)
        {
          continue;
        }

        foreach (var stackFrame in stackFrames)
        {
          if (stackFrame.HasValue && stackFrame.Symbol is not null)
          {
            sampleProto.LocationId.Add(GetLocationId(stackFrame.Symbol));
          }
          else
          {
            // TODO(henrika): improve...
            Console.Error.WriteLine("Invalid stackFrame");
          }
        }

        _profile.Sample.Add(sampleProto);
      }

      _profile.Comment.Add(GetStringId($"Exported by IdleWakeups from {Path.GetFileName(outputFileName)}"));

      using (FileStream output = File.Create(outputFileName))
      {
        using (GZipStream gzip = new GZipStream(output, CompressionMode.Compress))
        {
          using (CodedOutputStream serialized = new CodedOutputStream(gzip))
          {
            _profile.WriteTo(serialized);
            return output.Length;
          }
        }
      }
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
      if (stackSymbol.Image is null)
      {
        // TODO(henrika): improve
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
        if (sourceFileName is null)
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

    Dictionary<int, IdleWakeup> _idleWakeupsByThreadId = new();

    Dictionary<string, long> _filteredProcessReadyingProcesses = new();

    Dictionary<int, long> _previousCStates = new();

    Dictionary<string, StackFrames> _readyingThreadStacksByAnalyzerString = new();

    Dictionary<string, StackFrames> _readiedThreadStacksByAnalyzerString = new();

    pb.Profile _profile = new pb.Profile();
  }
}

/* ----- snippets
 
    // processId: 0
    // imageName: ntoskrnl.exe
    // imagePath: C:\Windows\System32\ntoskrnl.exe
    // functionAddress: 0xFFFFF80615BFE300
    // functionName: SwapContext

    // processId: 2520
    // imageName: KernelBase.dll
    // imagePath: C:\Windows\System32\KernelBase.dll
    // functionAddress: 0x00007FFD17F019D0
    // functionName: WaitForSingleObjectEx
    // 
    // processId: 2520
    // imageName: chrome.dll
    // imagePath: C: \Users\henri\AppData\Local\Google\Chrome SxS\Application\98.0.4742.0\chrome.dll
    // functionAddress: 0x00007FFCB39E1D50
    // functionName: base::WaitableEvent::TimedWait

    // sourceFileName: C:\b\s\w\ir\cache\builder\src\base\message_loop\message_pump_win.cc
 
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
