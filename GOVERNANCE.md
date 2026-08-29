# Governance

How decisions get made here, who makes them, and how that changes. Written down because
"ask the maintainer" is a process too - it is just an undocumented one, and a project
asking to be adopted should say which one it runs.

## Today: one maintainer

PerspectiveGraph has a single maintainer ([MAINTAINERS.md](MAINTAINERS.md)), who decides
what ships. That is the honest description of a project at this size, not an aspiration to
a committee it does not have.

What it means in practice:

- **Design decisions and scope are the maintainer's.** The [roadmap](ROADMAP.md) says what
  is planned and, as importantly, what this deliberately is not becoming.
- **Every change goes through a pull request** with the same gates, including the
  maintainer's own: the checks in CI are not advisory, and they are the same ones a
  contributor's branch runs.
- **Disagreement is settled in the open**, in the issue or the pull request. If you think a
  decision is wrong, the argument to make is a technical one - this project's whole posture
  is that a claim you can check beats one you have to accept.

## Deciding what gets built

Roughly in order of what moves the project:

1. **A false positive or a miss with a reproducer.** Something the engine claims that is not
   true, or a route it should have found and did not, is the most valuable report this
   project can receive - and the
   [CloudGoat benchmark](backend/testdata/cloudgoat/README.md) is where a fix for one gets
   pinned so it stays fixed.
2. **Something a real deployment cannot do.** A gap found by running it beats a gap found by
   reading about it.
3. **The roadmap**, which is ordered by impact rather than by date.

Open an issue before writing code for anything on the roadmap, so the shape can be agreed
before the work exists. Small fixes need no ceremony.

## Becoming a maintainer

There is no committee to join and no minimum contribution count. What earns commit rights
is a track record the maintainer can point at: several merged changes, held to the gates in
[CONTRIBUTING.md](CONTRIBUTING.md), and reviews of other people's work that caught something
real. Ask, or be asked.

This matters more than it looks: a single maintainer is a real risk to anyone adopting
this, and the honest mitigation is not a promise of availability but a project that someone
else can pick up - which is why [SUPPORT.md](SUPPORT.md#continuity) documents exactly what a
fork would need to replace.

## Releases

Releases are cut by [release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org): a `feat:` makes a minor, a
`fix:` a patch, and the CHANGELOG is generated rather than written from memory.

There is **no fixed cadence**. A release happens when something is worth releasing, which
in practice has meant several a week during active development. What is promised instead of
a schedule is in [SUPPORT.md](SUPPORT.md): fixes land on the newest release, security fixes
have a clock, and the interface is governed by
[API stability](docs/API-STABILITY.md) so that upgrading is boring.

## Security decisions

Vulnerability reports do not go through this process - they go through
[SECURITY.md](SECURITY.md), privately, and the maintainer decides on disclosure timing with
the reporter. Nothing about a security fix waits for a discussion in public.

## Changing this document

By pull request, like everything else.
