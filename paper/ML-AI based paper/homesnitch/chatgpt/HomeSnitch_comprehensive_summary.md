# HomeSnitch: Behavior Transparency and Control for Smart Home IoT Devices

## Comprehensive technical summary and replication guide

**Paper:** TJ O'Connor, Reham Mohamed, Markus Miettinen, William Enck, Bradley Reaves, and Ahmad-Reza Sadeghi. *HomeSnitch: Behavior Transparency and Control for Smart Home IoT Devices*. ACM WiSec 2019. DOI: [10.1145/3317549.3323409](https://doi.org/10.1145/3317549.3323409).

**Purpose:** explain the paper end-to-end, distinguish implemented mechanisms from proposed extensions, identify the missing artifacts that affect reproduction, and provide a practical plan for using the accompanying Python 3.12 notebook with the YourThings packet captures.

---

## 1. Executive summary

HomeSnitch is a network-level monitoring and control framework for smart-home IoT devices. Its key claim is that encrypted IoT traffic can still reveal **semantic device behaviors** through the shape of the client/server dialogue. Instead of decrypting payloads, HomeSnitch reconstructs **application data unit (ADU) exchanges** from TCP/IP header traces and calculates 13 numerical features describing throughput, burstiness, synchronicity, and connection duration. A supervised classifier maps each completed flow to a behavior triple:

```text
(<vendor>, <model>, <activity>)
```

Examples include:

```text
(Ring, Doorbell, Motion-Upload)
(WeMo, MotionSensor, Upload-Motion)
(TP-Link, HS110, Firmware-Download)
```

The intended control loop is:

1. Observe traffic at a commodity router.
2. Reconstruct application-dialogue structure from TCP headers.
3. Classify each connection as a known semantic behavior, or report it as unknown.
4. Maintain context about devices and prior flows.
5. Translate user policy into SDN/OpenFlow rules.
6. Log, pass, drop, reject, or redirect future matching traffic.

The supervised-learning result is strong: on the authors' labeled YourThings-derived corpus, Random Forest achieved **99.69% accuracy**, **94.66% recall**, and **93.93% F1** under stratified 10-fold cross-validation. The novelty-detection experiment uses the maximum class probability as an acceptance score. At a threshold of **0.89**, the authors report **11.96% unknown-behavior miss rate (UBMR)** and **96.82% true-positive rate (TPR)**.

The paper also evaluates an in-home deployment with 20 devices over two days. The authors collected 34,109 labeled exchanges, observed that 76.22% of traffic was encrypted, found that heartbeat behavior accounted for 55.09% of flows, and obtained a 99.40% cross-validation score on the deployment-specific labeled data.

The main caveat is reproducibility. The paper does **not** release a turnkey pipeline. It identifies `adudump` as the ADU extractor and scikit-learn as the ML library, but it does not publish the exact HomeSnitch preprocessing code, exact Random Forest hyperparameters, the 148-class semantic label manifest, or the operational Ryu/OpenFlow source. The accompanying notebook is therefore a transparent and configurable **reproduction scaffold**, not a claim of byte-for-byte equivalence with the authors' prototype.

---

## 2. Problem statement

Smart-home devices are difficult to inspect and control because:

1. Payloads are often encrypted.
2. Protocols are frequently proprietary.
3. The market is heterogeneous: implementations differ across vendors and even across models from the same vendor.
4. Ordinary network policy is too coarse. Blocking a destination IP or an entire device may remove useful functionality together with invasive functionality.

The authors want to expose and mediate activities such as:

- Heartbeats.
- Firmware checks and downloads.
- Motion uploads.
- Audio/video uploads.
- Configuration changes.
- Unlock actions.
- Analytics and reporting.

The user-facing abstraction is not “this device contacted an IP address.” It is “this Ring Doorbell attempted a motion upload.”

### Threat model

HomeSnitch assumes a residential LAN with smart-home devices behind a consumer router. The adversary may compromise devices through remote exploitation, NAT traversal, lateral movement, physical access, or abuse of a cloud-side service. The malicious outcome may include surveillance, exfiltration, credential theft, physical effects, or compromise of other hosts.

Scope limitations are explicit:

- The prototype focuses on IP-based, connection-oriented traffic.
- ZigBee, Bluetooth, NFC, and similar protocols are orthogonal future-work problems.
- The paper does not solve informed mimicry attacks, where a compromised device deliberately shapes malicious traffic to resemble allowed behavior.

---

## 3. Architecture

### 3.1 Consumer deployment

Figure 1 on page 3 presents the intended system: IoT devices connect through a consumer router running HomeSnitch; a user device receives behavior reports and submits preferences; a security provider can distribute updated signatures and policies.

The network is the enforcement point because the IoT firmware itself may be unmodifiable, vulnerable, or malicious.

### 3.2 Data plane and control plane

Figure 2 on page 3 separates:

- **Data plane:** Open vSwitch (OVS) on the router.
- **Control plane:** a Ryu SDN application, hosted on a Raspberry Pi in the prototype.
- **Behavior classifier:** assigns semantic labels to traffic.
- **Context monitor:** stores historical device/flow context.
- **Policy enforcer:** translates behavior-aware policy into OpenFlow actions.

The router uses OpenWrt with OpenFlow support. Wi-Fi and Ethernet interfaces are bound into one OVS bridge so the LAN can retain a flat address space. This is important because IoT devices often fail in more complex segmented topologies.

### 3.3 Behavior labels are device-specific

The behavior label is:

```text
(<vendor>, <model>, <activity>)
```

The authors initially wanted activity labels that transcended vendors and models, but found that implementations materially changed the dialogue structure. The original Ring Doorbell and Ring Pro are a concrete example. Device specificity improves accuracy but limits generalization: HomeSnitch does not learn a universal model of “motion upload”; it learns a model-specific implementation signature.

---

## 4. ADU-based representation

### 4.1 Why HomeSnitch does not use payloads, IPs, ports, or DNS as ML features

Payload inspection fails when protocols are encrypted. Destination IPs, ports, and DNS names can change or be manipulated. HomeSnitch therefore uses content-agnostic structural features.

The paper uses `adudump`, which reconstructs application-layer exchanges from TCP/IP header traces. The key units are:

- **Sequence:** a single directional application exchange.
- **ADU:** the entire bidirectional dialogue in one connection, bounded by teardown or flow timeout.

A signed dialogue pattern may look like:

```text
[203, -4, 43, -5]
```

Positive values can represent device-to-server bytes, while negative values represent server-to-device bytes. Appendix B on page 12 includes this kind of pattern in the behavior report.

### 4.2 Why ADUs can reveal behavior

The paper observes that smart-home communication is often sequential. Devices are narrow-purpose and much processing occurs server-side, so client and server frequently take turns. Repeated behaviors produce repeated dialogue shapes even when the payload is encrypted.

### 4.3 Reproduction boundary

HomeSnitch states that it uses `adudump`, but it does not report the exact command line, timeout, quiet-time threshold, output schema, retransmission handling, or post-processing code.

The accompanying notebook implements a portable approximation:

1. Stream IPv4 TCP metadata with `tshark`.
2. Keep flows involving a mapped IoT IP.
3. Deduplicate retransmitted payload ranges approximately using TCP sequence numbers.
4. Group payload-bearing packets into directional sequences.
5. Split same-direction sequences after a configurable quiet-time gap.
6. Close flows on FIN/RST, timeout, or PCAP end.
7. Compute the paper's 13 features.

This is suitable for testing the technique. It is not guaranteed to emit the exact ADUs produced by the authors' `adudump` pipeline.

---

## 5. The 13 features

Table 1 on page 4 defines the classifier input.

| # | Feature | Category | Paper importance |
|---:|---|---|---:|
| 1 | Average bytes from IoT device per sequence | Throughput | 0.213104 |
| 2 | Average bytes from server per sequence | Throughput | 0.072519 |
| 3 | Aggregate server bytes sent over ADU | Throughput | 0.105775 |
| 4 | Aggregate IoT-device bytes sent over ADU | Throughput | 0.117552 |
| 5 | Minimum bytes from IoT device in a sequence | Burstiness | 0.038917 |
| 6 | Minimum bytes from server in a sequence | Burstiness | 0.038344 |
| 7 | Maximum bytes from server in a sequence | Burstiness | 0.079063 |
| 8 | Maximum bytes from IoT device in a sequence | Burstiness | 0.135909 |
| 9 | Standard deviation of bytes between server sequences | Burstiness | 0.054491 |
| 10 | Standard deviation of bytes between IoT-device sequences | Burstiness | 0.050798 |
| 11 | Server sequences per ADU | Synchronicity | 0.013566 |
| 12 | IoT-device sequences per ADU | Synchronicity | 0.016211 |
| 13 | Total connection time | Duration | 0.063750 |

The three most influential features are:

- Average bytes from the IoT device per sequence.
- Maximum bytes from the IoT device in a sequence.
- Aggregate IoT-device bytes over the ADU.

Together, the paper says they account for 46.65% of the decision estimate.

### Interpretation

- **Throughput:** separates data-intensive activities from light transactional ones.
- **Burstiness:** separates event-driven actions, such as motion-triggered uploads.
- **Synchronicity:** captures how many turns occur in the client/server exchange.
- **Duration:** distinguishes brief transactions from longer-lived reporting or streaming behavior.

The prose discusses inter-arrival times as part of burstiness, but Table 1 lists byte-size standard deviations rather than explicit time-gap features. For reproduction, Table 1 is the authoritative feature list unless original source code provides additional detail.

---

## 6. Labels: the real bottleneck

### 6.1 Supervised evaluation labels

The main accuracy experiment uses timestamped behavior labels. Each ADU must be associated with a semantic class such as:

```text
(Ring, Doorbell, MotionUpload)
```

The public YourThings page provides raw PCAP files and a device-to-local-IP mapping. It does not appear to publish the HomeSnitch authors' exact 148-class semantic label manifest or timestamp windows. That missing artifact is the largest barrier to exact numerical reproduction.

The notebook accepts a manifest with columns:

| Column | Meaning |
|---|---|
| `start_time` | Inclusive start timestamp |
| `end_time` | Inclusive end timestamp |
| `device_ip` | Local IP address |
| `vendor` | Vendor |
| `model` | Model |
| `activity` | Human-readable behavior |
| `pcap_name` | Optional capture-file restriction |
| `notes` | Optional provenance |

Build this file from activation scripts, experiment logs, or manually correlated time windows.

### 6.2 DBSCAN bootstrapping for a new home

For the two-day empirical deployment, the authors use DBSCAN to discover recurring clusters, then manually assign semantic labels by correlating observed user actions and inspecting behavior reports.

DBSCAN solves pattern discovery, not semantic grounding. A cluster is not automatically “motion upload.” Human context is still necessary.

---

## 7. Model comparison

The paper compares three supervised classifiers under stratified 10-fold cross-validation:

| Model | Accuracy | Recall | F1 |
|---|---:|---:|---:|
| k-Nearest Neighbor | 99.32% ± 0.12 | 87.97% ± 2.16 | 86.35% ± 2.56 |
| Gradient Boost | 64.70% ± 42.10 | 53.55% ± 33.51 | 51.72% ± 32.72 |
| Random Forest | **99.69% ± 0.06** | **94.66% ± 1.21** | **93.93% ± 1.40** |

Random Forest is selected not only for classification accuracy, but also for novelty rejection. HomeSnitch needs probability scores that do not indiscriminately pull unseen behaviors into known classes.

### Missing hyperparameters

The paper does not specify:

- Random Forest tree count, depth, split criteria, or class weighting.
- kNN value of `k`.
- Gradient Boost configuration.
- Random seeds.
- Preprocessing details.

The notebook exposes explicit defaults. Do not claim exact table reproduction without the authors' original settings.

---

## 8. Unknown-behavior detection

### 8.1 Leave-one-behavior-out procedure

For each class:

1. Remove every sample of that class from training.
2. Train on all remaining classes.
3. Predict the removed samples.
4. Record the maximum class-probability score.
5. Reject a sample as unknown if the score is below a threshold.

The paper defines **Unknown Behavior Miss Rate (UBMR)** as the percentage of samples from unseen classes that fail to be identified as new. In operational terms, those samples are incorrectly accepted as existing behaviors.

### 8.2 Threshold

The reported operating point is:

- Threshold: **0.89**
- UBMR: **11.96%**
- TPR: **96.82%**

Section 4.1 contains a wording inconsistency and says “0.89%.” Section 6.1 uses `0.89`, which is consistent with a classifier probability and the ROC discussion. Use `0.89`, not `0.0089`.

### 8.3 Interpretation

A rejected sample is not automatically malicious. It is a new or poorly matched pattern requiring review.

Threshold tuning is a security/usability trade-off:

- Lower threshold: fewer alerts, but more novel activity is silently absorbed into known classes.
- Higher threshold: better novelty detection, but more false alerts.

---

## 9. Evaluation

### 9.1 RQ1: classification accuracy

The paper describes the YourThings-derived accuracy corpus as:

- 46 devices.
- 148 semantic behaviors.
- More than 2,239 cloud endpoints.
- Captures from 13–19 April 2018.

A later public YourThings artifact describes 45 devices and 13 PCAPs totaling about 150 GB across March and April 2018. Treat the paper's corpus as a derived view rather than assume the public download is already packaged in the exact HomeSnitch format.

### 9.2 RQ2: performance impact

The authors use iPerf to compare:

- Baseline router.
- Ryu `SimpleSwitch`.
- HomeSnitch.

For a single physical wireless connection, Table 3 on page 7 reports:

| Test | Throughput | Latency |
|---|---:|---:|
| Baseline | 15.848 ± 0.087 Mbps | 183.988 ± 2.154 ms |
| Ryu SimpleSwitch | 15.332 ± 0.096 Mbps | 278.552 ± 3.024 ms |
| HomeSnitch | 15.375 ± 0.238 Mbps | 283.452 ± 4.333 ms |

The SDN path adds roughly 100 ms latency while retaining about 97.01% of baseline throughput. Figure 4 on page 7 shows a similar pattern as parallel wireless connections increase.

This experiment cannot be reconstructed from PCAPs alone. It requires an OpenWrt/OVS router, Ryu controller, controlled Wi-Fi conditions, and repeated iPerf runs. The notebook includes a CSV analysis template, not a dataplane emulator.

### 9.3 RQ3: required training samples

The authors remove one class, then incrementally add samples back and score the remaining samples. They report averages of:

- **58.82 samples** to achieve 90% prediction confidence.
- **62.28 samples** to achieve 95% prediction confidence.

The notebook implements this experiment with configurable sample-count steps. Full 1-to-200 sweeps across every class are expensive.

---

## 10. In-home empirical study

The authors deploy HomeSnitch in an author's residence with 20 active devices for two days.

Key findings:

- 76.22% of traffic was encrypted.
- More than 34,000 application exchanges were recorded.
- Semantic names were manually assigned by correlating user-driven activity with clusters and reports.
- Heartbeats accounted for 55.09% of flows.
- The top 35 behaviors accounted for 90.39% of exchanges.
- The labeled deployment dataset achieved 99.40% cross-validation accuracy.

Figure 6 on page 9 visualizes the top 35 behaviors over 48 hours. Repetitive heartbeat rows appear as periodic patterns; event-driven activities appear as bursts. This is the most intuitive illustration of why behavior-level reporting is more useful than raw flow logs.

### Cross-deployment transfer

Table 4 on page 9 reports:

| Device | ADUs | Accuracy |
|---|---:|---:|
| Amazon Echo Dot | 302 | 90.40% |
| B&D Crockpot | 914 | 98.47% |
| Canary Security Camera | 15,426 | 98.88% |
| Hue Light Bridge | 2,362 | 99.58% |

The Ring Doorbell did not transfer cleanly because the model differed. That is a material limitation: the features are destination-agnostic, but signatures remain model- and version-sensitive.

---

## 11. Behavior reporting

Appendix B on page 12 shows a report with:

- Devices exhibiting a behavior.
- Top destination ports.
- Top destination IPs and DNS names.
- Periodicity.
- Identical signed ADU patterns.
- Recent flows.
- Similar clusters.
- Sent and received bytes.
- Duration statistics.

The paper excludes destinations and ports from the ML features but uses them for interpretation and enforcement. That distinction is sound:

- Structural features make classification more robust.
- Destination metadata makes reports understandable and can constrain policy.

The notebook includes a compact offline report function.

---

## 12. Policy and enforcement

HomeSnitch policy follows:

```text
Action Device Behavior Context
```

Supported actions include:

```text
alert | log | pass | drop | reject | redirect
```

Supported contexts include:

- Time period.
- Encrypted versus unencrypted connection.
- Presence or absence of a management device on the LAN.

Example rules from the paper:

```text
drop Ring-Doorbell, [Ring,Doorbell,Motion-Upload], (T: 0100-0300)
log WeMo-BabyCamera, [WeMo,BabyCamera,Firmware-Update], (C: unencrypted)
reject LockState-Lock, [Lockstate,Lock,Unlock], (M: notpresent)
```

### Enforcement mechanism

The classifier works on completed flows. The prototype therefore mines historical flow-level information to install rules for future matching traffic.

- `pass` and `drop`: direct flow modifications.
- `reject`: controller forges a TCP reset.
- `redirect`: controller rewrites fields.

This design is pragmatic but not instantaneous for never-before-seen behaviors.

### Policy experiment

The authors block Ring Doorbell motion uploads for ten minutes:

- 407 packets dropped.
- 31,462 bytes dropped.
- Blocked events did not later appear in the app.

They repeat with a D-Link motion sensor:

- 26 packets dropped.
- 1,936 bytes dropped.
- The device buffered the motion data and uploaded it after the restriction expired.

This is a crucial operational lesson: dropping traffic does not guarantee the privacy outcome a user expects. Device buffering behavior matters.

The notebook provides an offline impact simulator. It does not configure OpenFlow.

---

## 13. Limitations and critical assessment

### 13.1 Mimicry attacks

A compromised device can shape malicious traffic to resemble an allowed signature. Header-only classification cannot rule this out. Allowlists, trusted endpoints, identity, and attestation can help, but the paper does not solve mimicry.

### 13.2 Full-flow dependence

Precise classification requires the complete flow. That limits real-time enforcement. The paper proposes partial-flow stochastic models as future work but does not implement them.

### 13.3 Semantic labeling is manual

Clustering finds recurring patterns. It does not name them. External observation is still required.

### 13.4 Device and firmware drift

Signatures can change across product revisions or firmware versions. A practical service needs version-aware signatures and continuous retraining.

### 13.5 Missing artifacts

Exact reproduction is blocked by missing:

- 148-class semantic label manifest.
- Exact `adudump` configuration and output.
- Exact preprocessing code.
- Exact model hyperparameters and seeds.
- Ryu/OVS source.

A rigorous replication should document every replacement choice.

---

## 14. Using the notebook with YourThings

Official data page:

- [https://yourthings.info/data/](https://yourthings.info/data/)

The public site lists:

- Device mapping CSV.
- Evaluation sheet.
- Three March device-evaluation PCAPs.
- Ten April network-evaluation PCAPs.

The raw files are commonly 10–13 GB each.

### Recommended sequence

1. Download the mapping file and one April PCAP.
2. Install `tshark`.
3. Open the notebook.
4. Keep `RUN_SYNTHETIC_DEMO = True` for a first end-to-end run.
5. Set `RUN_SYNTHETIC_DEMO = False`.
6. Set the PCAP glob, mapping CSV, and output directory.
7. Extract one PCAP.
8. Inspect ADU distributions and signed patterns.
9. Create a small timestamped behavior manifest.
10. Validate supervised classification.
11. Scale only after the pipeline is plausible.

### Do not naively merge PCAPs

Process each PCAP chronologically, reconstruct connection-level ADUs, then concatenate feature rows. Do not blindly concatenate packet files without considering:

- Timestamp order.
- Capture boundaries.
- Flow timeout.
- TCP tuple reuse.
- Capture overlap.
- Connections spanning file boundaries.

The notebook processes files independently and flushes active flows at each PCAP boundary. This is a defensible starting point for day-level captures.

### Technique validation versus exact paper reproduction

These are distinct goals:

- **Technique validation:** determine whether ADU features and Random Forest separate behaviors on your own labeled data.
- **Exact reproduction:** recreate the authors' reported numbers on the exact 148-class corpus.

The first is achievable with public PCAPs and careful labeling. The second requires artifacts not published with the paper.

---

## 15. Notebook contents

The companion Python 3.12 notebook includes:

1. Dependency checks.
2. YourThings path configuration.
3. Flexible device-mapping loader.
4. Streaming TCP extraction using `tshark`.
5. Portable ADU reconstruction.
6. Exact 13-feature calculation.
7. Timestamp-window semantic label assignment.
8. Synthetic demo data.
9. Stratified 10-fold comparison of Random Forest, kNN, and Gradient Boost.
10. Feature importance.
11. Confidence CDF.
12. Leave-one-behavior-out novelty detection and UBMR sweep.
13. Required-training-sample experiment.
14. DBSCAN cluster discovery.
15. Behavior reporting.
16. Offline policy-impact simulation.
17. Optional iPerf CSV analysis template.
18. Model and feature export.

---

## 16. Bottom line

The strongest contribution is not Random Forest. The contribution is the combined design:

- ADU-level representation.
- Semantic device-specific labels.
- Novelty rejection.
- Human-readable reports.
- SDN-mediated control.

The technique is plausible and practically useful because narrow-purpose IoT devices often emit stable encrypted traffic structures. The weak point is reproducibility: the public PCAPs exist, but the semantic labels and precise preprocessing pipeline do not. Treat reproduced numbers as implementation-specific unless the original artifacts are obtained.

---

## References

1. O'Connor, TJ, et al. “HomeSnitch: Behavior Transparency and Control for Smart Home IoT Devices.” ACM WiSec 2019. [DOI](https://doi.org/10.1145/3317549.3323409).
2. YourThings official data page. [https://yourthings.info/data/](https://yourthings.info/data/).
3. Alrawi, Omar, et al. “SoK: Security Evaluation of Home-Based IoT Deployments.” IEEE Symposium on Security and Privacy, 2019.
4. Terrell, Jeff, et al. “Passive, Streaming Inference of TCP Connection Structure for Network Server Management.” Traffic Monitoring and Analysis, 2009.
