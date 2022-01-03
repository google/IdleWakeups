// Copyright 2022 Google Inc. All Rights Reserved.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using Microsoft.Windows.EventTracing.Cpu;

namespace IdleWakeups
{
    class ProfileAnalyzer
    {
        public struct Options
        {
            public string EtlFileName { get; set; }
            public decimal TimeStart { get; set; }
            public decimal TimeEnd { get; set; }
            public HashSet<string> ProcessFilterSet { get; set; }
            public bool Tabbed { get; set; }
        }

        struct IdleWakeup
        {
            public long ContextSwitchCount { get; set; }
            public int ProcessId { get; set; }
            public ChromeProcessType ProcessType { get; set; }
            public string ThreadName { get; set; }
        }

        struct ChromeProcessType
        {
            public ChromeProcessType(string type, string subType)
            {
                Type = type;
                SubType = subType;
            }
            public string Type { get; set; }
            public string SubType { get; set; }
        }

        public ProfileAnalyzer(Options options)
        {
            _options = options;
        }

        private ChromeProcessType GetChromeProcessType(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine))
                return new ChromeProcessType("", "");

            const string kProcessTypeParam = "--type=";
            const string kRendererProcessType = "renderer";
            const string kExtensionProcess = "extension";
            const string kExtensionParam = "--extension-process";
            const string kUtilityProcessType = "utility";
            const string kUtilitySubTypeParam = "--utility-sub-type=";
            const string kBrowserProcessType = "browser";
            const string kChrashpadProcess = "crashpad-handler";

            string type = kBrowserProcessType;
            string subtype = "";

            var commandLineSplit = commandLine.Split();
            foreach (string commandLineArg in commandLineSplit)
            {
                if (commandLineArg.StartsWith(kProcessTypeParam))
                {
                    type = commandLineArg[kProcessTypeParam.Length..];
                    if (type == kChrashpadProcess)
                    {
                        // Shorten the tag for better formatting.
                        type = "crashpad";
                    }
                    else if (type == kRendererProcessType && commandLine.Contains(kExtensionParam))
                    {
                        // Extension processes are renderers with '--extension-process' on the command line.
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

        public void AddSample(ICpuThreadActivity sample)
        {
            var contextSwitch = sample.SwitchIn.ContextSwitch;

            var timestamp = contextSwitch.Timestamp.RelativeTimestamp.TotalSeconds;
            if (timestamp < _options.TimeStart || timestamp > _options.TimeEnd)
                return;

            var switchInImageName = contextSwitch.SwitchIn.Process.ImageName;
            var switchOutImageName = contextSwitch.SwitchOut.Process.ImageName;

            // Check if all processes shall be analyzed when switched in (filter set to '*') or if a
            // filter has been set (e.g. 'chrome.exe') and it contains the process name switching in.
            if (_options.ProcessFilterSet == null ||
                _options.ProcessFilterSet.Contains(switchInImageName))
            {
                _wallTimeStart = Math.Min(_wallTimeStart, timestamp);
                _wallTimeEnd = Math.Max(_wallTimeEnd, timestamp);

                _filteredProcessContextSwitch++;
                if (switchOutImageName == "Idle")
                {
                    _filteredProcessIdleContextSwitch++;

                    var switchInThreadId = contextSwitch.SwitchIn.ThreadId;

                    IdleWakeup iwakeup;
                    if (!_idleWakeupsByThreadId.TryGetValue(switchInThreadId, out iwakeup))
                    {
                        // A new thread ID was found: update the context-switch counter and add the rest of the
                        // information about the detected idle wakeup. These values are only stored once.
                        iwakeup.ContextSwitchCount++;
                        iwakeup.ProcessId = contextSwitch.SwitchIn.Process.Id;
                        iwakeup.ThreadName = contextSwitch.SwitchIn.Thread.Name;

                        string commandLine = contextSwitch.SwitchIn.Process.CommandLine;
                        ChromeProcessType processType = GetChromeProcessType(commandLine);
                        iwakeup.ProcessType = processType;

                    }
                    else
                    {
                        // Thread ID already exists: only update the context-switch counter for this key.
                        iwakeup.ContextSwitchCount++;
                    }

                    _idleWakeupsByThreadId[switchInThreadId] = iwakeup;
                }
            }
        }

        public void WriteSummary()
        {
            // Console.WriteLine($"Analysis by IdleWakeups from {Path.GetFileName(_options.EtlFileName)}");

            string sep = _options.Tabbed ? "\t" : " : ";

            if (_wallTimeStart < _wallTimeEnd)
            {
                decimal durationMs = (_wallTimeEnd - _wallTimeStart) * 1000;
                Console.WriteLine("{0,-25}{1}{2:F}", "Duration (msec)", sep, durationMs);
            }

            Console.Write("{0,-25}{1}", "Process filter", sep);
            if (_options.ProcessFilterSet != null)
            {
                foreach (var process in _options.ProcessFilterSet)
                {
                    if (!_options.Tabbed)
                        Console.Write($"{process} ");
                    else
                        Console.Write($"{process}\t");
                }
            }
            else
            {
                Console.Write("*");
            }
            Console.WriteLine();

            Console.WriteLine("{0,-25}{1}{2}", "Context switches (On-CPU)", sep, _filteredProcessContextSwitch);
            Console.WriteLine("{0,-25}{1}{2}", "Idle wakeups", sep, _filteredProcessIdleContextSwitch);
            Console.WriteLine("{0,-25}{1}{2:F}", "Idle wakeups (%)",
                sep, 100 * (double)_filteredProcessIdleContextSwitch / _filteredProcessContextSwitch);
            Console.WriteLine();

            var sortedIdleWakeupsByThreadId = new List<KeyValuePair<int, IdleWakeup>>(_idleWakeupsByThreadId);
            sortedIdleWakeupsByThreadId.Sort((x, y)
                => y.Value.ContextSwitchCount.CompareTo(x.Value.ContextSwitchCount));

            string composite = "{0,6}{1}{2,6}{3}{4,-12}{5}{6,-20}{7}{8,-55}{9}{10,6}";
            sep = _options.Tabbed ? "\t" : " ";
            foreach (var idleWakeup in sortedIdleWakeupsByThreadId)
            {
                Console.WriteLine(composite,
                  idleWakeup.Key, sep,
                  idleWakeup.Value.ProcessId, sep,
                  idleWakeup.Value.ProcessType.Type, sep,
                  idleWakeup.Value.ProcessType.SubType, sep,
                  idleWakeup.Value.ThreadName, sep,
                  idleWakeup.Value.ContextSwitchCount);
            }

            var totalContextSwitchCount = _idleWakeupsByThreadId.Sum(x => x.Value.ContextSwitchCount);
            Console.WriteLine(composite,
                "", sep,
                "", sep,
                "", sep,
                "", sep,
                "", sep,
                totalContextSwitchCount);
        }

        private readonly Options _options;

        private long _filteredProcessContextSwitch;

        private long _filteredProcessIdleContextSwitch;

        private decimal _wallTimeStart = decimal.MaxValue;
        private decimal _wallTimeEnd = 0;

        private Dictionary<int, IdleWakeup> _idleWakeupsByThreadId = new();
    }
}