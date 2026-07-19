# Notes

## Summary

This document contains notes on the development of this plugin. Each section is
timestamped because it's written like a log and reflects and evolution in my understanding
of this project over time.

## 2026-07-19

The initial prototype of this plugin was written via LLMs (Claude Sonnet 4.6). It is also
written to work with the following channel:

- https://prefix.dev/github-releases

This release channel provides signature bundles for each package. An example of one of these
is available here:

- https://prefix.dev/github-releases/win-64/7zip-26.01-h9490d1a_0.conda.v0.sigs

Right, now the code is highly specific to working with just this channel
(e.g. `conda_sigtore.verifier.is_github_releases_package`).

To make this plugin a little more useful, we'll want to expand the channels it accepts
(should probably be set by the user with good defaults?), and we'll also want to allow
the user to optionally define the specific claims they might want to see. For example,
if we were using our own conda channel via GitHub actions, we could only accept artifacts
that were created via a partiuclar GitHub org/owner and action running (e.g. `release.yaml`).

### TODO for the repo itself

Right now the plugin downloads the `.v0.sigs` bundles everytime it runs. This is not ideal
because these files don't change. Next steps are implementing a cache to store these bundles.

Additionally, I'm also going to add a new setting to expose a list of trusted channels. This
will replace the `is_github_releases_package` function and make channel verification more
flexible.

### Later that day...

I implemented the above changes and there's now a working demo as a conda plugin.
