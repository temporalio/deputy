# Time travel: WORKING and `@{...}` refs

Deputy embraces Git’s ref model so you can answer “what changed?” and “when did it change?” precisely.

## Working tree compare (WORKING)

When you run `deputy` (or `deputy diff`) with no args inside a repo:

- default: compares default branch → `HEAD`
- if dependency manifests/lockfiles have uncommitted changes: compares default branch → `WORKING`

You can always be explicit:

```console
$ deputy diff main WORKING
```

Shorthand: `.` can be used for the working tree in many places:

```console
$ deputy diff main .
```

## Time-based references

Git supports time expressions via `@{...}` (quote these to avoid shell expansion):

```console
$ deputy diff "HEAD@{yesterday}" HEAD
$ deputy diff "main@{1.week.ago}" main
$ deputy diff "main@{3.month.ago}" main
$ deputy diff "HEAD@{1.year.ago}" HEAD
```

Supported shorthands inside `@{...}`:

- now, yesterday
- N.second(s).ago: s, sec, second, seconds
- N.minute(s).ago: m, min, minute, minutes
- N.hour(s).ago: h, hr, hour, hours
- N.day(s).ago: d, day, days
- N.week(s).ago: w, wk, week, weeks
- N.month(s).ago: mo, mon, month, months (calendar-aware)
- N.year(s).ago: y, yr, year, years (calendar-aware)

## Why this matters

Time-based refs let you answer questions like:

- “What dependencies did we have *before* we merged that refactor?”
- “Which dependency upgrades landed in the last week?”
- “What was our vulnerability posture a year ago?”

Pair time-based refs with historical OSV views:

```console
$ deputy diff v1.0.0 v2.0.0 --as-of=2022-12-31
```

See also:
- `docs/concepts/targets-and-refs.md`
- `docs/commands/diff.md`
- `docs/examples/historical-analysis.md`

