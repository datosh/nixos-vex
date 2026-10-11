# Stable channel support

The feed and the reference system only cover nixos-unstable. Add a stable
release (e.g. 26.05) as a second reference target: it changes less often and
is likely what security-minded users run.

Open questions:
- one feed for both channels, or one per channel
- a second reference host
- the extra CI and triage load
- the kernel LTS line in `kernel-cna-triage.py`
- signed release tags, if consumers of a stable channel follow tags

# Opt-in statements (`unless` / blacklist marker)

Conditions today must hold on a stock system: when one fails, its statements
are dropped with a warning. Some predicates work the other way round. For
example, "module X is in `boot.blacklistedKernelModules`" is false on a stock
system and only true when a user opts in. Statements with such a predicate
should be kept when it holds and dropped silently (no warning) otherwise.

Many of the acknowledged kernel findings already tell the user to blacklist a
module. With opt-in statements, doing so would also clear the finding from
their scan. Hardware-gated cases (e.g. qla2xxx) may fit too.

Candidates from the shadow triage (2026-10-09), `affected` until this exists:
- CVE-2026-53124 (ublk): only the ublk server can trigger it;
  `/dev/ublk-control` is root-only unless a udev rule widens it
- CVE-2026-64341 (iowarrior): needs the device, and its nodes are root-only
  unless a udev rule widens them
- CVE-2026-53257 (cfg80211): an unprivileged user can only create a radio via
  `mac80211_hwsim`, which has no autoload alias
- CVE-2026-46311 (amdgpu): the user-queue ioctl is off unless
  `amdgpu.user_queue` is set

Open questions:
- marker syntax: a second marker kind, or a property of the condition
- whether `affected` becomes `not_affected` when the module is blacklisted, and
  with which justification
- whether a blacklist is enough: it stops alias autoloading (including from
  unprivileged user namespaces) but not an explicit `modprobe` by root;
  `install <mod> /bin/false` is stronger
- how the flake checks cover it
