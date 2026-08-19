#!/usr/bin/env bash
# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Starts, stops, and reports on the key resolver.
#
#   ./resolver.sh start     idempotent; a resolver already running is left alone
#   ./resolver.sh stop      idempotent
#   ./resolver.sh status
#   ./resolver.sh log       follow the log
#
# The resolver holds every key and answers kube-apiserver's lookups over a unix
# socket. It runs on the host, and the socket reaches the control plane node
# through a read-only bind mount declared in kind.yaml.
#
# One resolver, not two. Nonce records live in its memory, so a second copy would
# accept replays the first had already recorded. The resolver refuses to start on
# a socket another one is listening on, and this script does not try to talk it
# out of that.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

bin=fixtures/bin/httpsig-resolver
keys=fixtures/resolver/keys.yaml
socket=fixtures/socket/resolver.sock
log=fixtures/resolver/resolver.log
pidfile=fixtures/resolver/resolver.pid

die() { echo "resolver.sh: $*" >&2; exit 1; }

# running reports whether the recorded pid is a live resolver, rather than a pid
# that has been recycled by something unrelated.
running() {
  [[ -f "$pidfile" ]] || return 1
  local pid
  pid="$(cat "$pidfile")"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  local exe
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
  # A pid file outlives the process that wrote it and pids are reused, so this is
  # what keeps "stop" from killing a stranger.
  #
  # The executable behind the pid, not its name. The kernel truncates a process
  # name to 15 characters and "httpsig-resolver" is 16, so a name comparison
  # silently never matches and reports every running resolver as dead. Comparing
  # /proc/pid/exe has no such edge, and it also tells this worktree's resolver
  # apart from another worktree's.
  [[ -n "$exe" && "$exe" == "$(realpath "$bin")" ]]
}

case "${1:-}" in
start)
  if running; then
    echo "resolver.sh: already running as pid $(cat "$pidfile")"
    exit 0
  fi
  [[ -x "$bin" ]] || die "no resolver at $bin. Run ./gen-fixtures.sh"
  [[ -f "$keys" ]] || die "no key file at $keys. Run ./gen-fixtures.sh"
  rm -f "$pidfile"

  mkdir -p "$(dirname "$socket")"
  # setsid so the resolver survives the shell that started it, which is what lets
  # up.sh start it and exit while the cluster keeps using it.
  # stdin from /dev/null as well as the output redirections, so the resolver holds
  # no descriptor of the caller's terminal and a script that starts it can exit.
  setsid "$bin" --keys "$keys" --listen "$socket" -v 2 </dev/null >"$log" 2>&1 &
  echo $! >"$pidfile"

  # Waited for rather than assumed. The API server is started next and fails to
  # start if the socket is not there, so a race here would surface as a cluster
  # that never comes up rather than as a resolver that was slow.
  for _ in $(seq 100); do
    [[ -S "$socket" ]] && break
    running || { echo "--- $log ---" >&2; cat "$log" >&2; die "the resolver exited during startup"; }
    sleep 0.1
  done
  [[ -S "$socket" ]] || die "the resolver never created $socket. See $log"

  echo "resolver.sh: listening on $socket as pid $(cat "$pidfile")"
  echo "resolver.sh: keys $keys, log $log"
  ;;

stop)
  if ! running; then
    echo "resolver.sh: not running"
    rm -f "$pidfile"
    exit 0
  fi
  pid="$(cat "$pidfile")"
  # TERM rather than KILL, so it stops gracefully and removes its own socket. A
  # KILL leaves the socket file behind; the resolver clears a stale one on its
  # next start, so that is recoverable rather than fatal, but it is not the
  # default path.
  kill "$pid"
  for _ in $(seq 50); do
    running || break
    sleep 0.1
  done
  if running; then
    # Still there after the grace period, so stop being polite. This leaves the
    # socket file behind, which the next start clears.
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pidfile"
  echo "resolver.sh: stopped"
  ;;

status)
  if running; then
    echo "resolver.sh: running as pid $(cat "$pidfile")"
    if [[ -S "$socket" ]]; then
      echo "  socket: $(stat -c '%A %U:%G %n' "$socket")"
    else
      echo "  socket: $socket is missing, though the process is running"
    fi
    # Counted out of the log, because there is no metrics endpoint: a demo resolver
    # with an HTTP server is two things to get wrong instead of one. Both lines are
    # logged at V(2), which is the verbosity this script starts the resolver at, so
    # a zero here means zero and not "not logged".
    # grep -c prints 0 and exits non-zero when nothing matches, so the count is
    # already right and only the exit status needs absorbing.
    echo "  lookups: $(grep -c '"Resolved key"' "$log" 2>/dev/null || true)"
    echo "  rejected nonces: $(grep -c '"Rejected nonce"' "$log" 2>/dev/null || true)"
  else
    echo "resolver.sh: not running"
    exit 1
  fi
  ;;

log)
  exec tail -f "$log"
  ;;

*)
  die "usage: $0 {start|stop|status|log}"
  ;;
esac
