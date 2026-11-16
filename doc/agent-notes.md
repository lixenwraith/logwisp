# Agent notes

What earlier agents learned that neither `AGENTS.md` nor the docs state.

- `go.sum` for a dependency version not yet tagged: its lines hash the
  module's files, so they are made from the dependency's branch before the
  tag exists. `golang.org/x/mod/zip.CreateFromVCS` at the branch head, then
  `dirhash.HashZip` gives the `h1:` line and `dirhash.Hash1` of its `go.mod`
  the other. Run the program on a published version first and compare with
  the `go.sum` here; a merge that changes the tree changes the hash.
- A version named in `go.mod` before its tag exists is asked of
  proxy.golang.org by every CI run, and the proxy remembers "not found" for up
  to 30 minutes after the tag is pushed. Go then fetches the module with git,
  which the Package workflow's `freebsd` VM and the image's builder lack:
  those two jobs fail at the download while the others pass, and pass on a
  rerun once `https://proxy.golang.org/<module>/@v/<version>.info` answers.
- The rc.d script runs nowhere but the Package workflow's `freebsd` job, in a
  FreeBSD VM: a change to `deploy/package/logwisp.rc` is verified by what
  that job asserts. Its shell runs with `nounset`, under which `/etc/rc.subr`
  does not load: source it after `set +u`.
- A PR touching a path of the Package workflow runs all its jobs on every
  push.
- `net/http` reads on, up to 256 KiB, into a request body its handler left
  unread, before it sends the answer: a test expecting an early refusal sends
  its body whole.
- A pipeline's exit status is its last command's: `go build ./... | tail`
  succeeds on a failed build. Gate on the build itself.
