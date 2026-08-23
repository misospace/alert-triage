# Changelog

## [0.2.0](https://github.com/misospace/alert-triage/compare/v0.1.9...v0.2.0) (2026-08-22)


### Features

* **enrich:** resolve GitOps repo path for alerted workloads ([9890957](https://github.com/misospace/alert-triage/commit/989095719d70d6f0be7aeee8bc6c53624a9c6d54))
* **enrich:** resolve GitOps repo path for alerted workloads ([81ca495](https://github.com/misospace/alert-triage/commit/81ca495e2c292c76ea9153bfc1152433ce071ba1)), closes [#34](https://github.com/misospace/alert-triage/issues/34)
* **github:** open PRs for fix proposals ([81b2fee](https://github.com/misospace/alert-triage/commit/81b2fee9a9fff696671b95dfb2e5867c173f7354))
* **github:** open PRs for fix proposals ([382b7cf](https://github.com/misospace/alert-triage/commit/382b7cf340c01ce6e275b37ec91526aa979b883e))
* query Prometheus-compatible backend for metric evidence ([ed4620c](https://github.com/misospace/alert-triage/commit/ed4620c8a9cf964ce5aa2122892423d513253801))
* query Prometheus-compatible backend for metric evidence ([9608127](https://github.com/misospace/alert-triage/commit/960812796dc03e7f36b720c2ddcf5771cd836eb8)), closes [#30](https://github.com/misospace/alert-triage/issues/30)


### Bug Fixes

* **ci:** sync Go toolchain versions ([6b8ed90](https://github.com/misospace/alert-triage/commit/6b8ed90cf58fbd5d4336df115294f87f22cd1dd8))
* copy go.sum into the builder stage ([f5523cb](https://github.com/misospace/alert-triage/commit/f5523cbe4ac8f2f8be32f3a67299cf9464570c37))
* format new tests ([6dc2ebe](https://github.com/misospace/alert-triage/commit/6dc2ebe60f5d1ade9842fc49e06519edf05296cb))
* format report test ([179667f](https://github.com/misospace/alert-triage/commit/179667f4c61c412e3e99b53f38d57c8fe7ddc546))
* **github:** harden PR path checks ([f25b767](https://github.com/misospace/alert-triage/commit/f25b767e8d867baf59d108922aecc4a9ab129f17))
* **http:** require WEBHOOK_TOKEN on /recent and /metrics ([5b55016](https://github.com/misospace/alert-triage/commit/5b550169f1f7afe80b800209536fa9a8b8f68d4d))
* **http:** require WEBHOOK_TOKEN on /recent and /metrics ([2b37335](https://github.com/misospace/alert-triage/commit/2b373353270a1e3e7847916d18591f4eb66e0264)), closes [#64](https://github.com/misospace/alert-triage/issues/64)
* pass prom to the shutdown drain and gofmt metrics_test ([8d5ada6](https://github.com/misospace/alert-triage/commit/8d5ada6695e476697d6ec67c7eb413fe8d3ca828))
* remove invalid report field ([e25ee8a](https://github.com/misospace/alert-triage/commit/e25ee8aaf815890fd45ff823b161b670dd39e3c0))
* resolve issue [#63](https://github.com/misospace/alert-triage/issues/63) ([b7b4fd1](https://github.com/misospace/alert-triage/commit/b7b4fd1697b75632f569d54b4db578387da752be))
* resolve issue [#65](https://github.com/misospace/alert-triage/issues/65) ([02199f0](https://github.com/misospace/alert-triage/commit/02199f01e211843e93b642457a3b7724e17e0a84))
* resolve issue [#65](https://github.com/misospace/alert-triage/issues/65) ([c6a3c3e](https://github.com/misospace/alert-triage/commit/c6a3c3e02667fabc54c661e60d88f12875ac8f24))
* **shutdown:** stop issuing narrate calls once the drain deadline is spent ([938fba4](https://github.com/misospace/alert-triage/commit/938fba4d6ddb86c5c90d9d924619cf82c9b2624b))
* **shutdown:** stop issuing narrate calls once the drain deadline is spent ([028bb99](https://github.com/misospace/alert-triage/commit/028bb99ccebf9f236cd6fe1564224a9d99d34ba0)), closes [#61](https://github.com/misospace/alert-triage/issues/61)
* skip Succeeded pods and score unhealthy pods by severity ([a8ee4ae](https://github.com/misospace/alert-triage/commit/a8ee4ae0b63a5595c22a348bd1a1a16457f5fa25)), closes [#38](https://github.com/misospace/alert-triage/issues/38)


### Chores

* **container:** update image gcr.io/distroless/static-debian13 (f7f8f72 → 1c2c046) ([31c02c1](https://github.com/misospace/alert-triage/commit/31c02c1a173ae258ad6318c8e11384bfd239c8b2))
* **container:** update image gcr.io/distroless/static-debian13 (f7f8f72 → 1c2c046) ([ab63706](https://github.com/misospace/alert-triage/commit/ab63706869a6db6567ec5c43be38f765704f33b9))


### Documentation

* issue contract for the autonomous loop ([71803ec](https://github.com/misospace/alert-triage/commit/71803ece63d72c5db228f0260855086dbbbae315))
* issue contract for the autonomous loop (template + AGENTS.md) ([f73a454](https://github.com/misospace/alert-triage/commit/f73a4540e7c809d20359058175908a81a371d02f))
