# 0005. Lock each ecosystem of the OSV cache with a file lock

- Status: accepted
- Date: 2026-11-13

## Context

ADR 0004 lets one run at a time use a cache: the scratch paths of a download (`.download-<ecosystem>`,
`.staging-<ecosystem>`, `.former-<ecosystem>`) are named after the ecosystem only, so that a run clears what a stopped
one left. The default cache of `forewarn match` is one directory per user (`specs/cli-match.md`, MCH-12): two CI jobs
on one self-hosted runner, or two terminals, now fetch the same ecosystem into it at the same time and can delete each
other's files.

Two ways to make the second run wait:

- a lock directory created atomically (`mkdir`): no dependency, but a run killed while holding it leaves it behind, and
  telling a stale lock from a live one needs a process id, a host name or an age, each wrong in some case (a reused
  pid, a container, a slow download);
- an advisory lock on a file (`flock` on Unix, `LockFileEx` on Windows): the system releases it when the process
  ends, however it ends, so no lock is ever stale. Since Rust 1.89 the standard library offers it
  (`File::lock`, `File::try_lock`), no crate needed; it is not guaranteed over a network file system.

## Decision

Each ecosystem of the cache has a lock file, `.lock-<ecosystem>` (its name starts with `.`, as the scratch paths),
created when missing and never removed (removing it would let two runs lock two different files). A fetch takes the
exclusive lock of that file, with `File::try_lock` polled every 200 ms, before it reads the freshness of the snapshot,
and keeps it until it is done with the ecosystem; it gives up after a bound the caller sets, 40 minutes by default,
longer than the 31.5 minutes the timeouts of a download allow (ADR 0004), so that a waiting run outlasts any live
download but not a suspended process. The workspace `rust-version` goes from 1.86 to 1.89.

A lock file another user of a shared cache created, which this run can only read, is locked through a read-only
handle. A fetch under `offline` that cannot open the lock file (a read-only cache filled elsewhere) reads without the
lock, and so does any fetch on a platform where the standard library has no file locks. A file system that refuses
the lock (`ENOLCK` on a network file system without a lock daemon) fails the fetch with "cannot use the cache" and the
system's reason, rather than letting two runs write unlocked.

## Consequences

- Two runs on one machine share a cache: the second waits, then reads the snapshot the first stored, or downloads
  again as its refresh policy says.
- A killed run never blocks the cache: its lock goes with its process.
- Different ecosystems do not wait for each other.
- A cache on a network file system shared by several machines is not protected.
- The bound covers one download, not a queue: a run behind two others that both download (`always`, an expired age)
  can give up although none is stuck.
- Runs that only read a snapshot also wait for each other while it is parsed.
- A run waits silently; the CLI says nothing while it waits.
- Building needs Rust 1.89.
