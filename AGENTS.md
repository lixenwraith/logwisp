# Working rules

It is the contract, not a suggestion.

## Comments

- A comment block is **at most 5 lines**. If the explanation needs more, the code
  is wrong or the explanation belongs in `doc/`.
- One line is the default. Comment *why*, never *what* — the code says what.
- No narrative, no history ("this used to…", "the plan proposed…"), no restating
  the diff, no essays on design philosophy. Git log and `doc/` hold those.
- No comment on a self-evident function. `// Lookup returns the address` above
  `func Lookup` is noise.
- Package doc blocks: 5 lines. Files do not get their own prologue.

## Files

- Do not create a file for one or a few helpers. Put them next to what uses them,
  or, if shared, in the package's main or type file.
- A new file needs a new concept, not a new function.
- Prefer editing an existing file over adding one.
- When you edit a file, bring its comments up to these rules; older files predate
  them.

## Scope

- Implement what was asked. Do not add tables, indirection, telemetry, tests or
  abstraction that nothing asked for.
  Exception: a task that explicitly invites additions gets the obvious ones, each
  named in the PR body; ask before any that is not obvious.
- One mechanism per problem. Two mechanisms doing one job is a bug or a refactor
  opportunity.
- Delete before adding. If a change is net-positive lines for a fix, justify it.
- Reverting an existing API to "improve" it is not a fix. Leave working code alone.
- Per-kind data lives in one table indexed by its kind; a new kind adds a row,
  never a switch or a parallel field.

## Tests

- One test per rule, named for the rule. No test that restates another.
- Test comments follow the 5-line limit.
- Do not pin lists that a human has to hand-maintain unless the pin prevents a
  real regression.
- Collapse tests: when a broader test covers a narrower one, delete the narrower
  one or do not add it. No test for simple behaviour that is unlikely to fail or
  is already exercised elsewhere.

## Docs and commits

- `doc/` is already long. Condense when you touch it; append only for a new concept
  or scope.
- A gap you are deferring goes in the "Not Implemented" list of the design doc it
  belongs to: extend the item, or add a concise one in the list's pattern.
- The repository describes the architecture, never a machine: docs and commands
  use placeholders for addresses, node names and credentials.
- PR bodies: what changed, why, how it was verified.
- One task, one branch, one PR. Divide the work into commits on that branch; do not
  split it across stacked PRs or multiple branches.
- Work that continues after its PR merged starts again from the latest main; never
  stack new commits on merged history.

## Gates

`go build ./...`, `gofmt -l` on changed files, and `go test` on the packages the
change touches.
- A change to platform-sensitive code also cross-builds the production target:
  `GOOS=freebsd GOARCH=amd64 go build ./cmd/logwisp`.
- Do not run `-race` tests unless investigating a known/suspected race issue; CI
  runs them.

## LogWisp

- Plugin options decode through `config.Scan`, never `lconfig.ScanMap`: unknown
  keys must fail at any depth. Set defaults on the options struct before the
  call; `TestEveryPluginRejectsUnknownKeys` covers every registered plugin.
- Network security has two seams: `tlsx` (TLS configs, startup warnings) and
  `authz` (every admission decision). Both return nil when disabled and every
  method tolerates a nil receiver; keep call sites branch-free on config.
- A plugin starts goroutines in `Start`, never in its constructor: a rejected
  reload discards constructed plugins without calling `Stop`. Reload is the only
  rotation path for certificates and secrets.
- The chain `Hello` is the protocol's extension point: optional fields only (old
  peers ignore unknown JSON); anything a peer must understand bumps
  `chain.ProtocolVersion`.
- Listeners and dialers are IPv4-only (`tcp4`). E2E scripts in `test/` need
  `bin/logwisp` and `--auto`, and each owns a port range and a gitignored run
  directory.
- Many older files lack a trailing newline and fail `gofmt -l`; format the files
  you change, not the tree.
