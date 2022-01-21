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
//
// Detects idle wakeups in Chrome in an ETW using TraceProcessing and exports symbolized callstacks
// related to these wakeups into a gzip-compressed protocol buffer (profile.proto).
//
// Explanations of the techniques can be found here:
// https://randomascii.wordpress.com/2020/01/05/bulk-etw-trace-analysis-in-c/
//
// See this blog post for details of the Trace Processor package used to
// drive this:
// https://blogs.windows.com/windowsdeveloper/2019/05/09/announcing-traceprocessor-preview-0-1-0/
// Note that this URL has changed once already, so caveat blog lector.
//
// The profile.proto is a protocol buffer and its format is described at:
// https://github.com/google/pprof/blob/master/proto/profile.proto
//
// See also https://randomascii.wordpress.com/2015/09/24/etw-central/ for more details.
//
// Comments are nomenclature follows the style used by WPA.

using System;
using System.Collections.Generic;
using System.IO;
using CommandLine;
using CommandLine.Text;
using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Symbols;

namespace IdleWakeups
{
  internal class Program
  {
    private class Options
    {
      [Usage(ApplicationAlias = "IdleWakeups")]
      public static IEnumerable<Example> Examples =>
#pragma warning disable CS8618
          new List<Example>() {
            new Example("Export idle wakeup callstacks to specified pprof profile using default options",
                        new UnParserSettings { PreferShortName = true },
                        new Options { etlFileName = "trace.etl", outputFileName = "profile.pb.gz" }),
            new Example("Export idle wakeup callstacks from all processes from 20s to 30s to default pprof profile",
                        new UnParserSettings { PreferShortName = true },
                        new Options { etlFileName = "trace.etl", processFilter = "*", timeStart = 20, timeEnd = 30 }),
            new Example("Export idle wakeup callstacks from specified process names",
                        new UnParserSettings { PreferShortName = true },
                        new Options { etlFileName = "trace.etl", processFilter = "audiodg.exe,dwm.exe" }),
            new Example("Export idle wakeup callstacks and thread/process ids",
                        new UnParserSettings { PreferShortName = true },
                        new Options { etlFileName = "trace.etl", includeProcessAndThreadIds = true }),
            new Example("Show summary of idle wakeup statistics but don't export to pprof",
                        new UnParserSettings { PreferShortName = false },
                        new Options { etlFileName = "trace.etl", writeSummary = true, exportToPprof = false }),
            new Example("Reduce time to load symbols by reading from symbol cache which already contains symbols",
                        new UnParserSettings { PreferShortName = false },
                        new Options { etlFileName = "trace.etl",  loadFromSymCache = true}),
          };

      [Value(0, MetaName = "etlFileName", Required = true, HelpText = "ETL trace file name.")]
      public string etlFileName { get; set; }

      [Option('o', "outputFileName", Required = false, Default = "profile.pb.gz", SetName = "pprof",
              HelpText = "Output file name for gzipped pprof profile.")]
      public string outputFileName { get; set; }

      [Option('p', "processFilter", Required = false, Default = "chrome.exe", SetName = "pprof",
              HelpText = "Filter for process names (comma-separated) to be included in the analysis. "
                         + "All processes will be analyzed if set to *.")]
      public string processFilter { get; set; }

      [Option("includeInlinedFunctions", Required = false, Default = false, SetName = "pprof",
             HelpText = "Whether inlined functions should be included in the exported profile (slow).")]
      public bool includeInlinedFunctions { get; set; }

      [Option("stripSourceFileNamePrefix", Required = false, Default = @"^c:/b/s/w/ir/cache/builder/", SetName = "pprof",
              HelpText = "Prefix regex to strip out of source file names in the exported profile.")]
      public string stripSourceFileNamePrefix { get; set; }

      [Option("timeStart", Required = false, Default = null, SetName = "pprof",
              HelpText = "Start of time range to analyze in seconds")]
      public decimal? timeStart { get; set; }

      [Option("timeEnd", Required = false, Default = null, SetName = "pprof",
              HelpText = "End of time range to analyze in seconds")]
      public decimal? timeEnd { get; set; }

      [Option("includeProcessIds", Required = false, Default = false, SetName = "pprof",
              HelpText = "Includes process ids in the exported profile.")]
      public bool includeProcessIds { get; set; }

      [Option("includeProcessAndThreadIds", Required = false, Default = false, SetName = "pprof",
              HelpText = "Includes process and thread ids in the exported profile.")]
      public bool includeProcessAndThreadIds { get; set; }

      [Option("splitChromeProcesses", Required = false, Default = true, SetName = "pprof",
              HelpText = "Splits chrome.exe processes by type in the exported profile.")]
      public bool splitChromeProcesses { get; set; }

      [Option('s', "writeSummary", Required = false, Default = false, SetName = "pprof",
              HelpText = "Writes a summary after analysis has completed.")]
      public bool writeSummary { get; set; }

      [Option("loadSymbols", Required = false, Default = true, SetName = "pprof",
              HelpText = "Whether symbols should be loaded.")]
      public bool? loadSymbols { get; set; }

      [Option("loadFromSymCache", Required = false, Default = false, SetName = "pprof",
              HelpText = "Loads symbols from cache where processed symbols are stored.")]
      public bool loadFromSymCache { get; set; }

      [Option("exportToPprof", Required = false, Default = true, SetName = "pprof",
              HelpText = "Whether results shall be exported to a gzipped pprof profile.")]
      public bool? exportToPprof { get; set; }

      [Option("listProcesses", Required = false, Default = false, SetName = "standalone",
             HelpText = "Whether all process names (unique) shall be printed out instead of running an analysis.")]
      public bool listProcesses { get; set; }

      [Option('t', "tabbed", Required = false, Default = false, SetName = "pprof",
              HelpText = "Print results as a tab-separated grid.")]
      public bool printTabbed { get; set; }

      [Option('v', "verboseOutput", Required = false, Default = false, SetName = "pprof",
              HelpText = "Set output to verbose messages.")]
      public bool verboseOutput { get; set; }
    }

    private static void Main(string[] args)
    {
      CommandLine.Parser.Default.ParseArguments<Options>(args).WithParsed(RunWithOptions);
    }

    private static void RunWithOptions(Options opts)
    {
      if (!File.Exists(opts.etlFileName))
      {
        Console.Error.WriteLine($"ERROR: File {opts.etlFileName} does not exist.");
        return;
      }

      var settings = new TraceProcessorSettings
      {
        AllowLostEvents = true,
        SuppressFirstTimeSetupMessage = true
      };

      var watch = new System.Diagnostics.Stopwatch();
      if (opts.verboseOutput)
      {
        watch.Start();
      }

      using (var trace = TraceProcessor.Create(opts.etlFileName, settings))
      {
        // Provides data from a trace about CPU thread scheduling, including context switches and
        // ready thread events. WPA: CPU Usage (Precise) table.
        var pendingCpuSchedulingData = trace.UseCpuSchedulingData();
        var pendingProcessData = trace.UseProcesses();
        var pendingSymbolData = trace.UseSymbols();

        trace.Process();

        if (opts.listProcesses)
        {
          // Skip the analysis for this option. Only print out the unique process names and then quit.
          var processData = pendingProcessData.Result;

          var allProcesses = new SortedSet<string>();
          foreach (var process in processData.Processes)
          {
            if (!allProcesses.Contains(process.ImageName))
            {
              allProcesses.Add(process.ImageName);
            }
          }

          Console.ForegroundColor = ConsoleColor.Yellow;
          Console.WriteLine($"{allProcesses.Count} unique process names found in " +
                            $"{Path.GetFileName(opts.etlFileName)}:");
          Console.WriteLine();
          Console.ForegroundColor = ConsoleColor.White;
          foreach (var process in allProcesses)
          {
            Console.WriteLine(process);
          }

          Console.WriteLine();
          return;
        }

        if (!opts.loadFromSymCache && (opts.loadSymbols ?? true))
        {
          ISymbolDataSource symbolData = pendingSymbolData.Result;
          var symbolProgress = new Progress<SymbolLoadingProgress>(progress =>
          {
            Console.Write("\r{0:P} {1} of {2} symbols processed ({3} loaded)",
                          (double)progress.ImagesProcessed / progress.ImagesTotal,
                          progress.ImagesProcessed,
                          progress.ImagesTotal,
                          progress.ImagesLoaded);
          });
          symbolData.LoadSymbolsAsync(
              SymCachePath.Automatic, SymbolPath.Automatic, symbolProgress)
              .GetAwaiter().GetResult();
        }

        if (opts.loadFromSymCache && (opts.loadSymbols ?? true))
        {
          var symbolData = pendingSymbolData.Result;
          symbolData.LoadSymbolsForConsoleAsync(SymCachePath.Automatic).GetAwaiter().GetResult();
          Console.WriteLine();
        }

        var cpuSchedData = pendingCpuSchedulingData.Result;

        var profileOpts = new ProfileAnalyzer.Options();
        profileOpts.EtlFileName = opts.etlFileName;
        profileOpts.IncludeInlinedFunctions = opts.includeInlinedFunctions;
        profileOpts.StripSourceFileNamePrefix = opts.stripSourceFileNamePrefix;
        profileOpts.TimeStart = opts.timeStart ?? 0;
        profileOpts.TimeEnd = opts.timeEnd ?? decimal.MaxValue;
        profileOpts.IncludeProcessIds = opts.includeProcessIds;
        profileOpts.IncludeProcessAndThreadIds = opts.includeProcessAndThreadIds;
        profileOpts.SplitChromeProcesses = opts.splitChromeProcesses;
        profileOpts.Tabbed = opts.printTabbed;
        profileOpts.Verbose = opts.verboseOutput;

        var analyzeAllProcesses = opts.processFilter == "*";
        if (!analyzeAllProcesses)
        {
          profileOpts.ProcessFilterSet = new HashSet<string>(
            opts.processFilter.Trim().Split(",", StringSplitOptions.RemoveEmptyEntries));
        }

        var profileAnalyzer = new ProfileAnalyzer(profileOpts);

        for (var i = 0; i < cpuSchedData.ThreadActivity.Count; i++)
        {
          if (i % 100 == 0)
          {
            var samples = cpuSchedData.ThreadActivity.Count;
            double percent = (double)i / samples;
            Console.Write($"\r{percent:P} {i} of {samples} samples processed");
          }

          // Get element from a list of merged CpuTimeSlices and ReadyThreadEvents.
          var threadActivity = cpuSchedData.ThreadActivity[i];
          if (opts.writeSummary)
          {
            profileAnalyzer.AddSummarySample(threadActivity);
          }
          if (opts.exportToPprof ?? true)
          {
            profileAnalyzer.AddPprofSample(threadActivity);
          }
        }
        Console.WriteLine();
        Console.WriteLine();

        if (opts.writeSummary)
        {
          profileAnalyzer.WriteSummary();
        }

        long outputSize = 0;
        if (opts.exportToPprof ?? true)
        {
          outputSize = profileAnalyzer.WritePprof(opts.outputFileName);
        }
        Console.WriteLine($"Wrote {outputSize:N0} bytes to {opts.outputFileName}");
        Console.WriteLine();

        if (opts.verboseOutput)
        {
          watch.Stop();
          Console.WriteLine($"Execution time: {watch.ElapsedMilliseconds} ms");
          Console.WriteLine();
        }
      }
    }
  }
}

