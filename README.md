# IdleWakeups

IdleWakeups detects idle-wakeups in Chrome (using an ETW trace) and exports symbolized callstacks
related to these wakeups into a gzip-compressed [protocol buffer](https://github.com/google/pprof/blob/master/proto/profile.proto).

It uses the [.NET TraceProcessing API](https://www.nuget.org/packages/Microsoft.Windows.EventTracing.Processing.All)
to process ETW traces.

This tool was built for processing ETW traces from Chrome, so the default values
of the flags are based on that use case. It uses `_NT_SYMCACHE_PATH` and `_NT_SYMBOL_PATH` for
symbolizing traces if set, otherwise it uses WPA defaults.

See this [blog post](https://blogs.windows.com/windowsdeveloper/2019/05/09/announcing-traceprocessor-preview-0-1-0/) for details of the Trace Processor package used to drive this.

More explanations of the techniques used in this program can be found [here](https://randomascii.wordpress.com/2020/01/05/bulk-etw-trace-analysis-in-c/).

The style and structure of this project is inspired by work in [EtwToPprof](https://github.com/google/EtwToPprof).

## Building

Build the provided Visual Studio Solution with VS 2022.

### NuGet dependencies (included in solution)
- [CommandLineParser v2.8.0](https://www.nuget.org/packages/CommandLineParser/2.8.0)
- [Microsoft.Windows.EventTracing.Processing.All v1.9.2](https://www.nuget.org/packages/Microsoft.Windows.EventTracing.Processing.All/1.9.2)
- [Google.Protobuf v3.19.3](https://www.nuget.org/packages/Google.Protobuf/3.19.3)

## Examples

Export idlewakeup callstacks found in `trace.etl` to specified pprof profile using default options:

    IdleWakeups -o profile.pb.gz trace.etl
  
Export idlewakeup callstacks from all processes from 20s to 30s to default pprof profile:

    IdleWakeups -p * --timeEnd 30 --timeStart 20 trace.etl

## Command line flags

    -o, --outputFileName    (Default: profile.pb.gz) Output file name for gzipped pprof profile.

    --listProcesses         (Default: false) Whether all process names (unique) shall be printed
                            out instead of running an analysis.

    -p, --processFilter     (Default: chrome.exe) Filter for process names (comma-separated) to be
                            included in the analysis. All processes will be analyzed if set to *.

    --timeStart             Start of time range to analyze in seconds

    --timeEnd               End of time range to analyze in seconds

    -s, --printSummary      (Default: false) Whether a summary shall be printed after the analysis
                            is completed.

    --loadSymbols           (Default: true) Whether symbols should be loaded.

    -t, --tabbed            (Default: false) Print results as a tab-separated grid.

    -v, --verboseOutput     (Default: false) Set output to verbose messages.

    --help                  Display this help screen.

    --version               Display version information.

    etlFileName (pos. 0)    Required. ETL trace file name.

## Disclaimer:

**This is not an officially supported Google product.**
