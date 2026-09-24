# Changelog

## [0.3.0](https://github.com/misospace/alert-triage/compare/v0.2.0...v0.3.0) (2026-09-24)


### Features

* **enrich:** enrich failed Pods with securityContext, PVC mounts, and same-claim siblings ([#140](https://github.com/misospace/alert-triage/issues/140)) ([9f270d7](https://github.com/misospace/alert-triage/commit/9f270d7bd6d4ce47a621ae9eafd65e345fba1067))
* **enrich:** surface Flux Kustomization path, components, and dependsOn for resolved workload ([#153](https://github.com/misospace/alert-triage/issues/153)) ([9d1ca18](https://github.com/misospace/alert-triage/commit/9d1ca18a65306e4288fdf222ef1f64a474582f2c))
* **enrich:** surface ownership chains for resolved jobs and pods ([#131](https://github.com/misospace/alert-triage/issues/131)) ([1dfcff9](https://github.com/misospace/alert-triage/commit/1dfcff98c28712a05f83a9f791c25722c7559e6a))
* **github:** classify reconciled commits against workload paths ([#157](https://github.com/misospace/alert-triage/issues/157)) ([1266b83](https://github.com/misospace/alert-triage/commit/1266b83a25a514091f1411f93d90ef74886d8138))
* **narrate:** support Anthropic messages API ([4e9b0ff](https://github.com/misospace/alert-triage/commit/4e9b0ffbfd894afd1240cf0bf8b7b96072aca21d))
* **narrate:** support Anthropic messages API ([7078989](https://github.com/misospace/alert-triage/commit/70789890a70274a8dbf5ba333b09f5f25e2592ad)), closes [#79](https://github.com/misospace/alert-triage/issues/79)
* **report:** split evidence into direct-subject and context tiers ([be2e13e](https://github.com/misospace/alert-triage/commit/be2e13e0dc2eaecac5c1ca8db70431462e30d14b)), closes [#136](https://github.com/misospace/alert-triage/issues/136)


### Bug Fixes

* **ci:** keep Go builder patch version aligned ([e517e16](https://github.com/misospace/alert-triage/commit/e517e16b0fed3dffac23f560e7a81d28fb57a166))
* **compact:** exit compact loop on context cancel ([54f9c47](https://github.com/misospace/alert-triage/commit/54f9c47b121a8bbeb817611131da59f81f1018a9))
* **compact:** exit compact loop on context cancel ([2a5bcda](https://github.com/misospace/alert-triage/commit/2a5bcda427e253c039953bc3d73b3a3ca640d015)), closes [#95](https://github.com/misospace/alert-triage/issues/95)
* **container:** update go toolchain ([5468bca](https://github.com/misospace/alert-triage/commit/5468bcac309b796979d86925396892a514828eca))
* **container:** update go toolchain ([0d423dc](https://github.com/misospace/alert-triage/commit/0d423dc53ca799dadd8da299c4e75151c3d13fab))
* **deliver:** thread caller context into GitHub issue and PR write arms ([3a4218a](https://github.com/misospace/alert-triage/commit/3a4218a1f1b49cc4d087b447703ab0845b9737df))
* **deliver:** thread caller context through Deliver so the Discord POST honours the SIGTERM drain ([a9714d9](https://github.com/misospace/alert-triage/commit/a9714d9cb299faf18d79b059d808115459b71fd8))
* **deliver:** thread caller context through Deliver so the Discord POST honours the SIGTERM drain ([30093de](https://github.com/misospace/alert-triage/commit/30093de5484fddf09ebad34e22870db75df641d2)), closes [#104](https://github.com/misospace/alert-triage/issues/104)
* **enrich:** address review findings on bounded fetchPodLogs concurrency ([4f6be22](https://github.com/misospace/alert-triage/commit/4f6be229d4efe188410a4f5a27633f34faaa93d1)), closes [#146](https://github.com/misospace/alert-triage/issues/146)
* **enrich:** capture terminated container status and fetch the correct log stream for failed Pods ([#149](https://github.com/misospace/alert-triage/issues/149)) ([62dab29](https://github.com/misospace/alert-triage/commit/62dab2938154921299a2b47c6b5e0ed1a96bf67a)), closes [#128](https://github.com/misospace/alert-triage/issues/128)
* **enrich:** initialise logsBackend HTTP client in newLogsBackend ([e145796](https://github.com/misospace/alert-triage/commit/e1457961f405b02a88b98f5025c9bf774e3688d8))
* **enrich:** initialise logsBackend HTTP client in newLogsBackend ([116fe2a](https://github.com/misospace/alert-triage/commit/116fe2a9d3452485daeb7776ab48125c6fd70924)), closes [#82](https://github.com/misospace/alert-triage/issues/82)
* **enrich:** propagate context.Context through kube.get and enrich helpers ([955a5ff](https://github.com/misospace/alert-triage/commit/955a5ffaa9f33cfdb956c80a2c956a6b09665892))
* **enrich:** propagate context.Context through kube.get and enrich helpers ([7af7f55](https://github.com/misospace/alert-triage/commit/7af7f55127568737428d152066821be43952ec00)), closes [#91](https://github.com/misospace/alert-triage/issues/91)
* **enrich:** remove dead fluxHelmPath rescue branch ([627e7f5](https://github.com/misospace/alert-triage/commit/627e7f5e7b6b575defaa451318c7bb6144567174))
* **enrich:** remove dead fluxHelmPath rescue branch ([9764840](https://github.com/misospace/alert-triage/commit/976484092a41f0faba825fe10765c10a3eb77ce4)), closes [#92](https://github.com/misospace/alert-triage/issues/92)
* **enrich:** scope events to resolved subjects ([#142](https://github.com/misospace/alert-triage/issues/142)) ([61ac1b7](https://github.com/misospace/alert-triage/commit/61ac1b71a211d71cf6ccc51b380dd2fdfddd28f4))
* **enrich:** scope the direct evidence tier to resolved subjects ([15f81e3](https://github.com/misospace/alert-triage/commit/15f81e3750566b0ddc0a11e7b58219a420d4c65b)), closes [#136](https://github.com/misospace/alert-triage/issues/136)
* **flux:** treat healthy Flux reconciles as neutral, not a deploy ([30aa330](https://github.com/misospace/alert-triage/commit/30aa33059d6e974e9ea00fcea1740186495da18a))
* **flux:** treat healthy Flux reconciles as neutral, not a deploy ([db53d20](https://github.com/misospace/alert-triage/commit/db53d20aae0850aa4b03cd6858f9a6eca0a80aa1)), closes [#133](https://github.com/misospace/alert-triage/issues/133)
* **grafana:** suppress Explore links when the group has no usable window ([adfa5a6](https://github.com/misospace/alert-triage/commit/adfa5a6669d00f18b6a60a7e219d564581f4a4e3))
* **grafana:** suppress Explore links when the group has no usable window ([6aa134b](https://github.com/misospace/alert-triage/commit/6aa134bd4d48260c6b0c29460226d5fa76cb6c4a)), closes [#106](https://github.com/misospace/alert-triage/issues/106)
* **history:** only record sightings after Deliver succeeds ([ba25adc](https://github.com/misospace/alert-triage/commit/ba25adc5ed28e1cce3091f5003cba394051d8922))
* **history:** only record sightings after Deliver succeeds ([70b85a7](https://github.com/misospace/alert-triage/commit/70b85a7d3565557bef529ed5e7cbb1c187df179b)), closes [#102](https://github.com/misospace/alert-triage/issues/102)
* **history:** release h.mu around the Compact rewrite so PriorSeen/Record do not stall on a slow rename ([be6c37f](https://github.com/misospace/alert-triage/commit/be6c37f3dbd8e32728094313e2aa4e6f65dfd805))
* **history:** release h.mu around the Compact rewrite so PriorSeen/Record do not stall on a slow rename ([aa81f18](https://github.com/misospace/alert-triage/commit/aa81f18a52aeffa1111a27d4f478924954f0fa32)), closes [#147](https://github.com/misospace/alert-triage/issues/147)
* **history:** survive an oversized JSONL line in History.load ([#165](https://github.com/misospace/alert-triage/issues/165)) ([2fdb482](https://github.com/misospace/alert-triage/commit/2fdb48267839ba7e5a02887920dad335f8df7964))
* **logs:** scope backend logs to resolved alert subjects ([404d973](https://github.com/misospace/alert-triage/commit/404d973ee69483e57a01a39730ae2f35a92c7cb6))
* **logs:** scope backend logs to resolved alert subjects ([8977e0d](https://github.com/misospace/alert-triage/commit/8977e0dc9c7a4fbe2401dc1e1645837265c894e9)), closes [#129](https://github.com/misospace/alert-triage/issues/129)
* **metrics:** escape backslashes in label values for PromQL ([#164](https://github.com/misospace/alert-triage/issues/164)) ([e3da929](https://github.com/misospace/alert-triage/commit/e3da92990a582a57896b5a55634be3370047d9f2)), closes [#161](https://github.com/misospace/alert-triage/issues/161)
* **metrics:** fire narration-failure counter on empty or unparseable replies ([37ec472](https://github.com/misospace/alert-triage/commit/37ec4729c859626a54d010ad17c563ed966f9012))
* **metrics:** fire narration-failure counter on empty or unparseable replies ([ade7cc9](https://github.com/misospace/alert-triage/commit/ade7cc931e013bd29b165782bf4e51a1cb9fdf49)), closes [#99](https://github.com/misospace/alert-triage/issues/99)
* **metrics:** scope direct metric evidence per source ([e47f8aa](https://github.com/misospace/alert-triage/commit/e47f8aaa17a66bbdbf50bcc7282712d2efbdc3b8)), closes [#136](https://github.com/misospace/alert-triage/issues/136)
* **narrate:** align anthropicReq struct fields and add reasoning-model fallback ([7515231](https://github.com/misospace/alert-triage/commit/75152313de7080759852b76179aed8f442676383))
* **propose:** gate unified-diff proposals on memory-pressure alerts ([#163](https://github.com/misospace/alert-triage/issues/163)) ([9f7c90b](https://github.com/misospace/alert-triage/commit/9f7c90bc8396dde85a36ed96ce006d736f77d424)), closes [#160](https://github.com/misospace/alert-triage/issues/160)
* **report:** propagate caller context into Narrate's model call ([8f3dcfb](https://github.com/misospace/alert-triage/commit/8f3dcfbb52c1ee6590dcf6e33d6616a7945ef2ab))
* **report:** propagate caller context into Narrate's model call ([d5dbb80](https://github.com/misospace/alert-triage/commit/d5dbb808a0e11e06b33968760df362c5ecefb2d9)), closes [#101](https://github.com/misospace/alert-triage/issues/101)
* **report:** sanitise pod logs to prevent Discord fence breakout ([e921eea](https://github.com/misospace/alert-triage/commit/e921eeada25334593d1ebdb925bd0fe55677a4e9))
* **report:** sanitise pod logs to prevent Discord fence breakout ([5263d01](https://github.com/misospace/alert-triage/commit/5263d0195345979233ebcabbdaea18b50064eae5)), closes [#103](https://github.com/misospace/alert-triage/issues/103)
* **report:** stop scoping no-subject negatives to an unseen subject ([aa0d5a6](https://github.com/misospace/alert-triage/commit/aa0d5a69969c16b1d2e58f6a2f24e8107959dac7)), closes [#136](https://github.com/misospace/alert-triage/issues/136)
* **report:** tier direct-subject evidence above contextual evidence ([367c51d](https://github.com/misospace/alert-triage/commit/367c51d39139a11626613ed530dfdc7509f8fc50))
* **shutdown:** pass cancellable context to flush loop and Narrate ([11bcd58](https://github.com/misospace/alert-triage/commit/11bcd5805c95d52cbec8cf3a5931e1c0df5a412f))
* **shutdown:** pass cancellable context to flush loop and Narrate ([9cfb5a7](https://github.com/misospace/alert-triage/commit/9cfb5a728b33c4457dbe069846caad40545bf67c)), closes [#100](https://github.com/misospace/alert-triage/issues/100)


### Performance Improvements

* **enrich:** bound per-pod log fetch concurrency in fetchPodLogs ([9fa2c7f](https://github.com/misospace/alert-triage/commit/9fa2c7f8791572e2f68e08734d2d426175f479d8))
* **enrich:** bound per-pod log fetch concurrency in fetchPodLogs ([a8755dd](https://github.com/misospace/alert-triage/commit/a8755ddd94c5d4db75f16ce9a6e56e6011597176)), closes [#146](https://github.com/misospace/alert-triage/issues/146)
* **metrics:** fetch /api/v1/rules once per flush and share across groups ([3d3d103](https://github.com/misospace/alert-triage/commit/3d3d1034ce0833d1b45d4621e3a2635b47d3be45))
* **metrics:** fetch /api/v1/rules once per flush and share across groups ([b310d49](https://github.com/misospace/alert-triage/commit/b310d497bb97f5945e629e4afc9d4b4bfd25da7e)), closes [#66](https://github.com/misospace/alert-triage/issues/66)


### Chores

* **container:** update image docker.io/library/golang (4cb7ac9 → 8a5910f) ([#169](https://github.com/misospace/alert-triage/issues/169)) ([8c9f709](https://github.com/misospace/alert-triage/commit/8c9f70999972a3b88a1beb70129aa3ce17e3a537))
* **container:** update image docker.io/library/golang (cf6fca6 → 4cb7ac9) ([#167](https://github.com/misospace/alert-triage/issues/167)) ([dc43526](https://github.com/misospace/alert-triage/commit/dc43526b45a05368858418483fe34ffdab87bc02))
* **container:** update image gcr.io/distroless/static-debian13 (1c2c046 → e2e927e) ([1d6f60b](https://github.com/misospace/alert-triage/commit/1d6f60bd1bfe43b1c89ada5bba3144eb906c8892))
* **container:** update image gcr.io/distroless/static-debian13 (1c2c046 → e2e927e) ([26a2295](https://github.com/misospace/alert-triage/commit/26a22950b20d2efc74d6c43cbec09ec46256c0d3))
* **deps:** add gopkg.in/check.v1 to go.sum for a complete module graph ([914f344](https://github.com/misospace/alert-triage/commit/914f344ce2d0de8c4f8c2087b873f1965c3226ed))
* **deps:** add gopkg.in/check.v1 to go.sum for a complete module graph ([c058467](https://github.com/misospace/alert-triage/commit/c058467149156999afb879de9fb9b24089fb75ff)), closes [#105](https://github.com/misospace/alert-triage/issues/105)
* **enrich:** resolve KubeJobFailed job_name alerts to the Job and its owned Pods ([f573ddf](https://github.com/misospace/alert-triage/commit/f573ddf1edee0afb793f5cbe31cea4fb43e0f7f6))
* **enrich:** resolve KubeJobFailed job_name alerts to the Job and its owned Pods ([833c5ed](https://github.com/misospace/alert-triage/commit/833c5ede6df8d4ca640e4a3cf79569efb5a5ad94)), closes [#127](https://github.com/misospace/alert-triage/issues/127)
* **enrich:** surface Job/Pod ownerReferences and controller identity in ownership chains ([4ac1d55](https://github.com/misospace/alert-triage/commit/4ac1d557c0f669bd74bcc3bff5f6ec2a8d809ec2))
* update native loop settings ([8fcc456](https://github.com/misospace/alert-triage/commit/8fcc45603441676fbf76f47d2620f6072d66b979))
* update native loop settings ([927d949](https://github.com/misospace/alert-triage/commit/927d9499d658458113836b0657d285c91361acdb))


### Documentation

* **metrics:** correct metricsHandler comment to reflect requireAuth wrapping ([e0b89c4](https://github.com/misospace/alert-triage/commit/e0b89c40287c077cbfce587a9497bfb0a835143d))
* **metrics:** correct metricsHandler comment to reflect requireAuth wrapping ([93eed29](https://github.com/misospace/alert-triage/commit/93eed290c0e884e88b36afafb89178e7e06f6918)), closes [#84](https://github.com/misospace/alert-triage/issues/84)


### Refactors

* **github:** drop dead CommentList field from ghIssue ([1deb222](https://github.com/misospace/alert-triage/commit/1deb222633fd1695f061028ae0450f9344457f01))
* **github:** drop dead CommentList field from ghIssue ([332e633](https://github.com/misospace/alert-triage/commit/332e63315e38ada8267b0b40330fbd8541c0c9ca)), closes [#98](https://github.com/misospace/alert-triage/issues/98)
* **grafana:** inline osGetenv indirection in envGrafanaURL ([56515ad](https://github.com/misospace/alert-triage/commit/56515ad8e8d4d46fc3b2c55ff0907df80fdb487e))
* **grafana:** inline osGetenv indirection in envGrafanaURL ([3b66bbf](https://github.com/misospace/alert-triage/commit/3b66bbf3f8a5ff1fbb7fd16f4b7286ee151626ec)), closes [#94](https://github.com/misospace/alert-triage/issues/94)
* **metrics:** remove dead EnrichMetrics method and its tests ([2120dec](https://github.com/misospace/alert-triage/commit/2120dec34eb158ba947cac23906092f290ad5683))
* **metrics:** remove dead EnrichMetrics method and its tests ([13f0f87](https://github.com/misospace/alert-triage/commit/13f0f87ec4dcbd419ca836ba275130c979796cea)), closes [#121](https://github.com/misospace/alert-triage/issues/121)

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
