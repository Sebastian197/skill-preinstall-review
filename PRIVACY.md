# Privacy policy: skill-preinstall-review

Last updated: 2026-10-18

skill-preinstall-review is a plugin that runs entirely on the user's own
computer. It has no server, no account and no telemetry. The author receives
no data from it.

## What it reads

- The files of the skill, plugin or marketplace the user asks it to review,
  from a local directory or a git repository the user names.
- Nothing else on purpose. It does not read the user's own credentials,
  environment variables, documents or other projects.

## What it writes

- `report.md` and `report.json` in a local directory the user chooses. They
  describe the reviewed package and what its code did in the sandbox.
- A Docker image on the user's machine (`preinstall-review-sandbox`), built
  on first use and reused afterwards.
- Temporary files, deleted when the review ends.

## What it sends or fetches over the network

- `git clone` of the repository the user asks it to review, from the host
  that repository lives on (for example GitHub). This uses the user's normal
  git setup, as any clone does.
- On first use only, `docker build` downloads the `debian:bookworm-slim`
  base image from Docker Hub and Debian packages from Debian's mirrors.

Nothing else leaves the machine. The code under review runs in a container
with no network access, and the decoy credentials planted there are random
values generated for that run; they are never real and never leave the
container.

## Personal data

The plugin does not collect, store or transmit personal data. A reviewed
package may itself contain names or email addresses (for example in its
manifest); those can appear in the local report and stay on the user's
machine.

## Data retention

The author retains nothing, because nothing is sent to the author. Local
reports and the Docker image remain on the user's machine until the user
deletes them.

## Contact

Questions about this policy: open an issue at
https://github.com/Sebastian197/skill-preinstall-review/issues
