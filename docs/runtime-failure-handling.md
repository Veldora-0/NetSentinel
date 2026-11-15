# Runtime Failure Handling

This note describes failure behavior implemented by the firewall manager and host telemetry worker. Firewall configuration defaults remain disabled with auto-block off and dry-run on; these details apply when the relevant subsystem is enabled as well.

## Firewall command failures

- A block is added to NetSentinel's in-memory managed list only after the real iptables chain is initialized and the DROP rule is inserted successfully. Initialization or insertion errors return a failed result and do not claim that the address is blocked.
- A failed unblock returns an error and keeps the address in the managed list. Expiration cleanup retries removal later, and an expired address remains reported as blocked until removal succeeds.
- A failed flush of the dedicated NetSentinel chain leaves the managed list intact. A successful flush affects only that chain, never global `INPUT`, `FORWARD`, or `OUTPUT` rules.
- In disabled or dry-run mode, block and unblock operations are simulated in memory and do not invoke iptables.

## Unavailable host telemetry

- If an individual psutil or operating-system metric cannot be read, the live snapshot uses JSON `null` for that metric. Other successfully collected metrics continue to be included in the snapshot.
- Host network rates are `null` until there is a valid prior counter baseline and enough elapsed time to calculate a rate. A measured rate of zero is distinct: it means counters were available and did not increase during the sample interval.
- The `host_telemetry` Socket.IO event and current telemetry endpoint can therefore contain null metric values. The frontend should show these as unavailable rather than as zero.

## Historical telemetry limitation

The current `host_telemetry` database schema requires the CPU, memory, disk, and network counter fields to be non-null. When a required metric is unavailable, persisting that incomplete snapshot fails and the database transaction is rolled back. Consequently, historical telemetry has no row for that sample; it does not store a fabricated zero. Optional load-average columns can store null. Allowing partially available samples in history requires a future schema and persistence change.

## Verification reference

The code change described above passed the 459-test backend suite and the frontend production build. Firewall command failure tests mock iptables; they do not execute real firewall modifications.
