# Resource usage for CI command spans

Enable collection for existing `otel_span [NAME] -- COMMAND [ARGS...]` calls:

```shell
export GLCI_OTEL_RESOURCE_USAGE=true
```

A configured `GLCI_OTEL_ENDPOINT`, valid `CI_TRACEPARENT`, and Ruby are prerequisites.
Collection is disabled by default. `GLCI_OTEL_RESOURCE_USAGE=true` enables CPU,
memory, and project-filesystem disk collection. CPU and memory require Linux
cgroup v2; disk and network collection support Linux independently of cgroups.
Network collection is disabled by default and additionally requires
`GLCI_OTEL_NETWORK_USAGE=true`. For network collection through the shell export
integration, export both variables:

```shell
export GLCI_OTEL_RESOURCE_USAGE=true
export GLCI_OTEL_NETWORK_USAGE=true
```

## Measurement scope

The collector resolves the current cgroup using `/proc/self/cgroup` and
`/proc/self/mountinfo`. Measurements include background work in that cgroup and
its descendants, not exclusively the wrapped command. Sibling service containers
and Docker-in-Docker workloads may be outside the measured subtree.

The first snapshot occurs in the existing context-preparation process. The second
occurs in the export process after execution. Some instrumentation overhead is
included. No additional Ruby launches are needed. A production-runner microbenchmark
measured about 7 ms of incremental resource-collection latency per call in Bash
and BusyBox. Representative-workload overhead remains unvalidated.

The exporter sets `ENRICHMENT_TIMEOUT_S` to one second. Resource preparation,
resource collection at export time, and failure classification each have an
independent one-second budget. These budgets are separate from the three-second
HTTP export timeout (`EXPORT_TIMEOUT_S`), so enrichment can add latency.
Network collection shares the existing one-second resource preparation and
collection budgets and adds no separate latency budget.

If resource enrichment times out, the exporter omits it and retains the base
span's timing and status. If failure classification times out, failed commands
use `gitlab.cicd.failure.category=user:unknown` and `gitlab.cicd.failure.source=exit_code`.
Successful commands receive no failure attributes.

## Attributes

All attributes use the prefix `gitlab.cicd.resource_usage.`:

| Suffix | Type | Meaning |
| --- | --- | --- |
| `scope` | String | `current_cgroup` |
| `source` | String | `cgroup_v2` |
| `cpu_time_seconds` | Double | Increase in cumulative CPU usage, summed across CPUs |
| `memory_start_bytes`, `memory_end_bytes` | Integer | Endpoint `memory.current` |
| `memory_limit_start_bytes`, `memory_limit_end_bytes` | Integer | Finite endpoint `memory.max` |
| `memory_headroom_start_bytes`, `memory_headroom_end_bytes` | Integer | Current cgroup limit minus its usage, clamped to zero |
| `memory_visible_ancestor_headroom_start_bytes`, `memory_visible_ancestor_headroom_end_bytes` | Integer | Minimum headroom among readable visible ancestors, each using its own limit and usage |
| `memory_events_high`, `memory_events_max`, `memory_events_oom`, `memory_events_oom_kill` | Integer | Interval increases in hierarchical `memory.events` counters |

Missing, unlimited, or malformed measurements are omitted. Counter resets omit
the affected deltas. Changed cgroup identity omits resource enrichment. These
conditions do not prevent ordinary timing/status export or change command outcomes.

## Interpretation

- CPU time can exceed wall time when work runs on multiple CPUs.
- Memory snapshots do not capture peaks or minimum headroom during execution.
- Accounted memory includes reclaimable cache. Low headroom does not by itself
  establish an imminent OOM.
- Ancestor budgets include competing descendants. Hidden ancestors are not
  observable, and host memory is not substituted for unknown limits.
- Memory-pressure events describe the subtree, not exclusively the command.
- Nested measurement windows overlap. Do not sum them as independent consumption
  or treat endpoint observations as a time-weighted memory distribution.

Compare equivalent commands and initial/retry attempts. Use the pipeline critical
path as well as resource usage when choosing optimizations.

## Architecture reference

The [CI Job Telemetry design](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/ci_job_telemetry/#step-runner-telemetry-integration)
proposes environment-specific collectors and span filters. This internal pilot
enriches existing script spans. Runner-native collection remains the long-term
path for executor-aware measurements, without adding a generic user-attribute API.

## Project filesystem snapshots

`GLCI_OTEL_RESOURCE_USAGE=true` enables disk snapshots for the filesystem
containing `CI_PROJECT_DIR`. The existing Ruby preparation and export processes each launch
one `stat` subprocess with a half-second timeout within the one-second
resource-enrichment budget. Both GNU and BusyBox `stat -f` support the machine-readable format; no
image dependency or Ruby launch is added.

Attributes use the `gitlab.cicd.disk.` prefix:

- `scope`: `project_filesystem`.
- `space_total_start_bytes`, `space_total_end_bytes`: filesystem capacity.
- `space_available_start_bytes`, `space_available_end_bytes`: blocks available
  to unprivileged processes, excluding reserved blocks.
- `inodes_available_start`, `inodes_available_end`: filesystem free inode count.

These are shared endpoint snapshots, not exclusive command consumption or minimum
availability. Quotas can impose lower budgets, including on free inodes. Separate
temporary, cache, or Docker storage filesystems are not measured. Low availability
does not prove an `ENOSPC` failure.

Missing paths, unsupported statistics, changed filesystems, and disk-only timeouts
omit disk attributes without suppressing cgroup measurements. A resource-enrichment
timeout omits both. Missing cgroups do not suppress disk snapshots. Disk snapshots
were observed in the parent pipeline of the
[production pilot](https://gitlab.com/gitlab-org/gitlab/-/pipelines/2929317223).
CNG collection and coverage across other runner topologies remain unvalidated.

## Network measurement contract

On Linux, the collector measures received and transmitted bytes for the current
network namespace when it contains exactly one non-loopback interface that is up.
It uses Ruby's standard-library `Socket.getifaddrs` to collect interface names,
indexes, and flags. It excludes interfaces with `IFF_LOOPBACK` or without `IFF_UP`
from selection, so inactive interfaces such as automatically added tunnels do not
make selection ambiguous. It does not assume an interface name such as `eth0`.
Network collection adds no Ruby process, subprocess, or dependency.

To disable network collection independently, unset `GLCI_OTEL_NETWORK_USAGE` or
set it to `false`. Keep `GLCI_OTEL_RESOURCE_USAGE=true` to retain CPU, memory, and
disk collection.

The collector reads counters from `/proc/net/dev`, bounded to 32 KiB. The complete
observable interface inventory, including loopback and inactive interfaces, must
match the counter inventory. It rechecks the interface inventory around each
counter read. Both snapshots must describe the same network namespace, identified
by device and inode, and the same interface inventory, including interface names,
indexes, loopback status, and up status.

These custom span attributes use the `gitlab.cicd.network.` prefix. They are not
standard OpenTelemetry network metrics or semantic-convention attributes.

| Suffix | Type | Meaning |
| --- | --- | --- |
| `scope` | String | `current_network_namespace` |
| `interface.name` | String | The selected non-loopback interface's name |
| `receive_bytes` | Integer | Interval increase in received bytes |
| `transmit_bytes` | Integer | Interval increase in transmitted bytes |

Zero-byte deltas are valid. Partial or unreadable observations, multiple
active non-loopback interfaces, counter resets, or changed namespace or interface
identity omit network attributes only. They do not suppress disk or cgroup
measurements, ordinary timing/status export, or change command outcomes. Missing
cgroups do not suppress network collection.

Interpret these measurements with the following limits:

- Counters include traffic from all processes sharing the namespace, including
  private-network traffic. They do not establish exclusive command consumption,
  internet egress, or billable transfer.
- Transfers made by helpers outside the job's namespace are excluded. This can
  include Docker-in-Docker workloads.
- Nested measurement windows overlap. Do not sum their deltas as independent
  consumption.
- Endpoint checks cannot detect an interface recreated between snapshots with
  the same observable identity, an interface that is brought up and down again
  between snapshots, or an intermediate counter reset that recovers above the
  starting value.
- The interval starts in context preparation and ends in the export process, so
  it includes some instrumentation overhead. Network measurement ends before its
  own telemetry export, but can include earlier exports from nested spans.

Local testing covers a Linux container with a single active non-loopback interface.
Production runner topology coverage and overhead remain unverified.
