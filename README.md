# foxprox

a WIP TUN device transparent network proxy/broker for policy-based sandboxing, primarily built for [sandfox](https://github.com/foxfirecodes/sandfox)

inspired by [passt/pasta](https://passt.top/passt/about/) and [slirp4netns](https://github.com/rootless-containers/slirp4netns)

## Alpha live smoke

After building, run the live bwrap/TUN smoke test with:

```sh
scripts/live-smoke-bwrap-tun.sh
```

See [docs/live-smoke.md](docs/live-smoke.md) for requirements, covered paths, and known alpha limits.
