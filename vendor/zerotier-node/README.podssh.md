# vendor/zerotier-node

ZeroTierOne's core, as podssh links it (T-733): `node/`, `include/`, `version.h`, and from `osdep/` the
`OSUtils` that `objects.mk`'s `CORE_OBJS` names and the headers that `node/` includes, at ZeroTierOne
commit `899352e` (2026-07-22), MPL-2.0 (`LICENSE-MPL.txt`); and the header-only
`ext/prometheus-cpp-lite-1.0` (MIT, its `LICENSE`) that `node/Metrics` includes. One file is changed (T-795): prometheus-cpp-lite's
`save_to_file.h` starts its saver's thread only when a file is given (`restart`), and joins it only when it runs, so
that `node/Metrics.cpp`'s global `saver`, which the core never gives a file, starts no thread before `main`: that
thread held root's capabilities past `podssh serve`'s drop and woke each 10 ms for the life of the process. The change
is `vendor/patches/zerotier-node/0001-saver-starts-no-thread-before-main.patch`.
`nonfree/` (the controller) and `service/` are not taken. `crates/podssh-zerotier/build.rs` builds it.
It is outside the workspace's rules of length, as `vendor/tailscale-rs` is.
