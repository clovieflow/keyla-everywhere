# Notices

## License

Keyla Everywhere is distributed under the **GNU General Public License, version 3
only**. The full text is in [`LICENSE`](LICENSE).

## Provenance

The gateway engine — request routing, protocol translation, provider adapters,
persistence, telemetry — is third-party code under the same GPL-3.0-only terms,
incorporated here as the starting point for this project.

| | |
|---|---|
| Project | Cartethyia |
| Source | <https://github.com/risunCode/Cartethyia> |
| Revision | branch `dev`, commit `382cf2308f4a09aeac0b5e2b1adf8fa7ace9319f` |
| License | GPL-3.0-only |

Its copyright and license are retained as the GPL requires. The engine was
incorporated as a single commit so the history of this repository begins at a
state that runs.

## Modifications

Every change made to the incorporated engine is recorded in
[`CHANGELOG.md`](CHANGELOG.md), with dates. In summary, this project adds and
maintains:

- the Keyla Everywhere console: an original editorial interface and
  Indonesian-first localization;
- the rebrand from the earlier project presentation to Keyla Everywhere,
  including the binary, crate, environment-variable, storage, and data-directory
  names;
- Bansos: publishing a subsidized key and the public page that hands it out;
- the `keyla` command-line tool;
- operational work across routing, provider handling, security and deployment.

Presentation and naming changes are kept separate from engine changes so
either can move independently.

## Warranty

This software is provided **without warranty**, as stated in the GPLv3.
