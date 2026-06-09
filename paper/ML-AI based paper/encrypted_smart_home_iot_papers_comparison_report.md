# Comparative Report: Encrypted Smart-Home IoT Traffic Analysis Papers

## Scope

This report compares three papers that analyze privacy and security risks in smart-home Internet-of-Things (IoT) network traffic when packet payloads are encrypted:

1. **Spying on the Smart Home: Privacy Attacks and Defenses on Encrypted IoT Traffic** — Noah Apthorpe, Dillon Reisman, Srikanth Sundaresan, Arvind Narayanan, and Nick Feamster; 2017 arXiv preprint.
2. **HomeSnitch: Behavior Transparency and Control for Smart Home IoT Devices** — TJ OConnor, Reham Mohamed, Markus Miettinen, William Enck, Bradley Reaves, and Ahmad-Reza Sadeghi; WiSec 2019.
3. **Peek-a-Boo: I see your smart home activities, even encrypted!** — Abbas Acar et al.; WiSec 2020.

The three papers are related, but they do **not** evaluate the same task. Their headline accuracy values should not be compared as though they were scores from a shared benchmark. They differ in adversary vantage point, protocol scope, unit of analysis, labels, datasets, and desired output.

---

## Executive synthesis

The papers form a useful progression:

- **Spying on the Smart Home** establishes the core privacy problem from a **WAN / ISP-like observer's** perspective. It shows that encrypted smart-home traffic still exposes device identity and user activities through metadata, especially traffic-rate changes. Its strongest contribution is not a sophisticated activity classifier; it is the argument that the leak is practical and that **independent link padding (ILP)** can mitigate it at acceptable cost.

- **HomeSnitch** turns encrypted-traffic analysis into a **defensive router capability**. Instead of inferring only whether a device was active, it classifies semantic device behaviors such as heartbeat, firmware update, and motion upload. It extracts **application data unit (ADU)** dialogue features from TCP/IP headers, classifies behavior triples with a Random Forest, detects unknown behaviors, and uses Software-Defined Networking (SDN) rules to enforce policy.

- **Peek-a-Boo** develops the most ambitious **attack pipeline**. A local wireless eavesdropper passively sniffs WiFi, ZigBee, and BLE traffic and attempts to infer device identity, whether a state transition occurred, which state or action occurred, and finally higher-level user activities. It combines packet-sequence metadata, supervised learning, automated time-series feature extraction, and a Hidden Markov Model (HMM). It is the closest of the three to an end-to-end activity inference attack, but it also has the most important reproducibility and evaluation caveats.

A practical way to distinguish them is:

| Question | Best-matching paper |
|---|---|
| Can an ISP-like observer infer private activity from encrypted IoT traffic? | **Spying on the Smart Home** |
| Can a home router classify and control device behaviors despite encryption? | **HomeSnitch** |
| Can a nearby passive sniffer reconstruct device states and user activities across WiFi, ZigBee, and BLE? | **Peek-a-Boo** |
| Which paper is the easiest starting point for reproducing a simple attack? | **Spying on the Smart Home** |
| Which paper explicitly evaluates on an independent reusable corpus? | **HomeSnitch** |
| Which paper is the closest match for multi-device user-activity inference research? | **Peek-a-Boo** |

---

## 1. Master comparison table

The criteria are columns and the papers are rows so that additional papers can be added as new rows.

| Paper | Year / venue | Primary objective | Perspective | Main observer or deployment vantage point | Protocol scope | Unit of analysis | Core technique | Primary output | Dataset scale | Headline results | Proposed defense or enforcement | Strongest contribution | Most important limitation |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Spying on the Smart Home** | 2017 arXiv preprint | Demonstrate that encrypted IoT metadata leaks private in-home activities and evaluate practical mitigations | Attack demonstration plus privacy defense | Passive last-mile network observer similar to an ISP; LAN visibility may optionally be available | Primarily Internet-facing IP traffic from WiFi-connected devices | Per-device flow and traffic-rate time series; aggregate bytes in consecutive samples and windows | Device identification using MAC organizational identifiers, DNS queries, or traffic-rate fingerprints; activity inference from traffic-rate changes; 3-nearest-neighbors proof of concept for device identification | Device type and privacy-sensitive activity indicators such as appliance on/off, sleep pattern changes, camera live streaming, camera motion events, and voice-assistant interaction timing | 7 laboratory devices; 6 devices in the traffic-rate fingerprinting experiment; controlled case studies for activities | 4 of 7 devices uniquely identifiable from DNS alone; greater than 95% device-identification accuracy for a range of window and sample sizes; non-audio/video traffic can be masked with at most 7.5 KB/s cover traffic; up to 40 KB/s for audio/video homes | VPN plus independent link padding (ILP), implemented using Linux traffic control, cover traffic, and token-bucket shaping | Clearly establishes the privacy problem at the ISP vantage point and quantifies the feasibility of traffic shaping | Activity inference is mostly shown through controlled case studies and visible traffic-rate correlations rather than a full end-to-end activity-classification benchmark |
| **HomeSnitch** | WiSec 2019 | Provide network-level transparency and control by classifying semantic IoT behaviors despite encryption and proprietary protocols | Defensive monitoring and enforcement system | Consumer router with SDN data plane and external controller | IP connection-oriented protocols; ZigBee, Bluetooth, and NFC are explicitly left for future work | TCP/IP flow reconstructed as a bidirectional application data unit (ADU) dialogue | `adudump` ADU extraction from TCP/IP headers; 13 dialogue features; Random Forest behavior classification; confidence threshold for unknown behavior; DBSCAN-assisted clustering for empirical labeling; SDN policy enforcement | Behavior triple: `<vendor, model, activity>`, such as Ring Doorbell motion upload; known or unknown behavior reports; access-control action | Independent YourThings corpus: 46 devices, 148 semantic behaviors, more than 2,239 cloud endpoints; separate 20-device, two-day home deployment with 34,109 labeled behaviors | Random Forest: 99.69% accuracy, 94.66% recall, and 93.93% F1 in stratified 10-fold cross-validation; threshold 0.89 yields 11.96% unknown-behavior miss rate and 96.82% true-positive rate; empirical home study reports 99.40% cross-validation score | SDN policy actions including alert, log, pass, drop, reject, and redirect based on device, behavior, and context | Moves beyond fingerprinting toward semantic behavior transparency, unknown-behavior detection, and actionable network policy | Requires complete flows for precise classification and relies on vendor/model-specific behavior patterns; mimicry attacks, non-IP protocols, first-occurrence enforcement, and model drift remain unresolved |
| **Peek-a-Boo** | WiSec 2020 | Infer device identity, state changes, specific states, and higher-level user activities from passively sniffed encrypted wireless traffic | Multi-stage privacy attack plus spoofed-traffic mitigation | Local attacker within wireless range; remote ISP-like attacker discussed but left out of scope | WiFi, ZigBee, and BLE | Packet-level Sequence of Packet Lengths and Times (SPLT), interval windows, time-series features, and HMM state vectors | Four-stage cascade: device identification, device-state detection, device-state classification, and user-activity inference; kNN, Random Forest, multiple classifiers, `tsfresh`, Extra Trees feature selection, and HMM | Device type, whether activity occurred, specific state/action, and composite user activity such as controlling a device remotely, walking inside the home, entering/exiting, or opening/closing doors and windows | 22 off-the-shelf IoT devices for traffic traces; controlled experiments repeated 20 times per device plus 1–2 hour uncontrolled multi-device background tests; separate user-activity environment | ZigBee device identification: 93% accuracy; device-state detection: average F1 of 88% with Random Forest and 91% with kNN; device-state classification: Random Forest held-out F1 of 94%; HMM activities: 93–100% accuracy depending on activity | Inject spoofed or falsified traffic to corrupt state detection and state classification; paper evaluates feature-level false-data injection and discusses app-based packet generation | Most complete attack decomposition and broadest protocol coverage; explicitly separates device events from multi-device user activities | The paper does not report a single propagated end-to-end success rate; its mitigation is not evaluated as a deployed online defense; several reporting inconsistencies and a printed F1-score formula error complicate replication |

---

## 2. Threat-model comparison

| Paper | Protected asset | Adversary or threat | Placement | Passive or active? | Information visible to the observer | Training-data assumption | Explicitly out of scope or unresolved |
|---|---|---|---|---|---|---|---|
| **Spying on the Smart Home** | Privacy of in-home activities and device usage | ISP-like passive observer or another network observer attempting to infer user behavior | Last-mile Internet path; may or may not also observe LAN traffic | Passive | Flow-level records such as IPFIX / NetFlow or packet captures; traffic rates; packet headers; optionally LAN MAC addresses; DNS queries where observable | Adversary can obtain labeled traffic from example smart-home devices and continuously monitor a target | VPN exit trust; deployment in constrained networks; device-specific bandwidth and latency trade-offs; simple activity case studies rather than a universal classifier |
| **HomeSnitch** | User control over device behaviors, including privacy-invasive or malicious actions | Compromised IoT device, remote attacker, malicious cloud-side behavior, or manufacturer behavior that violates user preferences | Defender-controlled router and SDN controller inside the home | The monitored device or remote attacker may be active; HomeSnitch itself observes and enforces | IP connection-oriented flows; TCP/IP header traces; complete flows for precise classification; router-level context such as time, encryption state, and management-device presence | Models can be trained from labeled behaviors or clustered observations; security service provider may distribute signatures and policies | Mimicry attacks; ZigBee, Bluetooth, NFC; precise real-time classification before a flow completes; privacy and quality issues in crowd-sourced signature sharing |
| **Peek-a-Boo** | Privacy of device inventory, device states, sensor events, and composite user activities | Nearby attacker, planted sniffer, or compromised device acting as a sniffer | Within RF range of the smart home | Passive attack; mitigation proposes generated traffic | Wireless metadata from WiFi, ZigBee, and BLE; unencrypted headers; MAC addresses where available; BLE advertisements; packet lengths; timing; direction | Attacker can collect traffic from the same brand and device type to train models; the paper assumes the `<brand, device-type>` identity is known by the end of stage 1 | Remote ISP attacker not fully evaluated; multi-user ambiguity; generalization across brand, model, firmware, and configuration; deployed mitigation overhead and detectability |

### Key distinction

The observer in **Spying on the Smart Home** is upstream of the home, while the observer in **Peek-a-Boo** is local to the wireless environment. This difference materially changes which metadata are available. For example, the ISP-like observer can see Internet endpoints but may lose individual-device visibility behind NAT or a hub. The local sniffer can use link-layer metadata but may not see IP-layer information when WiFi encryption protects it. **HomeSnitch** is different again: it is not primarily an eavesdropper attack. It is a router-based defensive monitor that intentionally has flow visibility inside the home.

---

## 3. Dataset and data-collection comparison

| Paper | Dataset source | Environment | Devices and scale | Collection procedure | Background traffic | Labels | Independent or self-collected? | Public-data or artifact status established by the PDF | Important caveats |
|---|---|---|---|---|---|---|---|---|---|
| **Spying on the Smart Home** | Laboratory captures produced by the authors | Raspberry Pi 3 Model B configured as 802.11n access point, with `hostapd`, `dnsmasq`, and `iptables` NAT | 7 devices: Sense Sleep Monitor, Nest Cam Indoor, Amcrest WiFi camera, Belkin WeMo switch, TP-Link smart plug, Orvibo socket, and Amazon Echo | Records pcaps and IPFIX records for traffic through the access point; fingerprinting proof of concept uses two hours of traffic from 6 devices with minimal user interactions; activity sections use controlled experiments per device | Fingerprinting experiment explicitly minimizes user interaction; no broad multi-device household background benchmark is reported | Device identities and manually induced events, such as WeMo transitions, Echo questions, sleep events, camera live streaming, and simulated motion | Self-collected | The PDF describes the setup but does not provide a release link for the authors' traces or shaping script | Strong for demonstrating feasibility; limited as a reusable activity-classification benchmark |
| **HomeSnitch** | YourThings corpus for main accuracy evaluation; separate residential deployment for empirical study | Commodity Linksys router with custom OpenWrt and Open vSwitch; Raspberry Pi 3 controller running Ryu | YourThings: 46 devices, 148 semantic behaviors, more than 2,239 cloud endpoints, collected 13–19 April 2018; empirical deployment: 20 devices over two days and 34,109 labeled behaviors | Extracts flow-level ADUs; main evaluation uses independent labeled corpus; empirical deployment records application exchanges and manually associates behavior clusters with user-driven events and descriptive reports | Empirical deployment naturally contains concurrent household device behavior, including frequent heartbeats; 55.09% of observed flows are heartbeat behaviors | Behavior triples `<vendor, model, activity>`; manual descriptive naming is applied after clustering and report inspection in the home deployment | Main evaluation is independent; empirical study is self-collected | The PDF explicitly identifies the independent YourThings corpus and cites its source. It does not provide a HomeSnitch code-repository link. Current download availability should be verified separately. | Main benchmark is well-suited to semantic device behaviors, but not necessarily to composite human activities across devices |
| **Peek-a-Boo** | Authors' laboratory traces plus a separate user-activity environment | Laboratory network for 22 devices; separate smart-home activity environment with Samsung SmartThings hub and sensors, Arlo camera, Philips Hue, Ecobee thermostat, and August lock | 22 off-the-shelf devices spanning WiFi, ZigBee, and BLE; stage-4 environment uses multiple sensors and devices | Controlled actions are repeated 20 times per device; uncontrolled tests configure several devices simultaneously, occasionally trigger actions, and record approximately 1–2 hours to capture background traffic; analysis is offline | Yes. The paper explicitly adds uncontrolled multi-device testing to capture background traffic | State-change labels, specific state/action labels, and six higher-level user-activity categories | Self-collected | The PDF does not provide a release link for the complete trace corpus or the full attack implementation | Stage 4 contains an internal reporting inconsistency: one passage says traffic was collected from 10 users, while the results passage says training data came from 15 people with 30 datasets |

### Background-traffic relevance

For research involving realistic household interference, **Peek-a-Boo** provides the clearest explicit collection design: controlled experiments for class coverage plus uncontrolled simultaneous-device periods for background traffic. **HomeSnitch** also observes naturally concurrent traffic in a residential deployment. **Spying on the Smart Home** uses a simpler setup intended to make the privacy leak visible and measurable.

---

## 4. Preprocessing, features, and machine-learning comparison

| Paper | Raw input | Preprocessing pipeline | Learning sample | Features used | Models used | Validation procedure | Unknown-behavior handling | Notes |
|---|---|---|---|---|---|---|---|---|
| **Spying on the Smart Home** | PCAP or IPFIX / NetFlow-like records from smart-home Internet traffic | Separate traffic into device flows; convert each device's traffic into a time series whose elements are bytes sent or received in consecutive `s`-second samples; split into `w`-second windows | Two-dimensional feature vector per traffic window | Mean and standard deviation of traffic amount in each window; paper notes that SYN/ACK proportions, packets per flow, and inter-packet interval distributions could be added | 3-nearest-neighbors for device-identification proof of concept | Stratified 10-fold cross-validation for device identification | Not a focus | Activity inference uses observed traffic-rate changes and controlled case studies rather than a general trained classifier |
| **HomeSnitch** | TCP/IP packet-header traces from IP connection-oriented flows | Run `adudump` to reconstruct bidirectional ADU exchanges from headers only; represent application dialogue as sequential client/server turns; calculate one feature vector per ADU | Thirteen-feature ADU vector per flow | Throughput: average and aggregate bytes from device/server; burstiness: min, max, and standard deviation of bytes per sequence; synchronicity: sequence counts per ADU; duration: total connection time. IP addresses, ports, and DNS are deliberately excluded from the classifier. | Random Forest selected as primary classifier; kNN and Gradient Boost compared; DBSCAN used to cluster empirical behaviors for labeling | Stratified 10-fold cross-validation on YourThings; leave-one-behavior-out procedure to assess unseen behavior detection | Confidence threshold; low-confidence samples are treated as unknown; threshold 0.89 gives the reported trade-off | Feature importance is interpretable: average bytes, maximum bytes, and aggregate bytes from the IoT device account for 46.65% of the Random Forest decision estimate |
| **Peek-a-Boo** | Captured wireless packets from WiFi, ZigBee, and BLE | Convert each flow into SPLT rows: `[timestamp, direction, packet length]`; derive stage-specific windows and feature vectors; state classification runs automated time-series feature extraction with `tsfresh`; feature selection uses Extra Trees; user-activity inference combines state, timing, controller, and location features into an HMM input array | Varies by stage: interval feature vector, time-series feature vector, or HMM state-array sequence | Stage 1: mean packet length, mean inter-arrival time, and packet-length standard deviation. Stage 2: mean packet length, mean inter-arrival time, and median absolute deviation of packet size. Stage 3: 795 `tsfresh` features reduced to 197, including energy, length, mean, median, skewness, entropy, standard deviation, variance, continuous-wavelet coefficients, FFT coefficients, and polynomial-fit coefficients. Stage 4: timing, sensor state, device state, controller state, and controller location. | Stage 1: kNN. Stage 2: Random Forest and kNN. Stage 3: SVC with RBF kernel, logistic regression, Random Forest, Naive Bayes, decision tree, kNN, AdaBoost, and XGBoost; Random Forest performs best. Stage 4: HMM. | Stage 3: 75% training data with 5-fold cross-validation and 25% held-out validation; other stages report task-specific evaluation | Not a central goal | The pipeline is richer than the other two papers but substantially harder to reproduce because each stage has different data assumptions and labels |

---

## 5. Detailed numerical-results comparison

### 5.1 Main reported results

| Paper | Device identification | Device-state detection | Specific behavior or state classification | Higher-level user activity | Runtime or deployment performance | Defense results | Interpretation caveat |
|---|---|---|---|---|---|---|---|
| **Spying on the Smart Home** | DNS uniquely identifies 4 of 7 devices; traffic-rate 3-NN classifier exceeds 95% accuracy over a range of sample/window choices for 6 devices | Not evaluated as a separate supervised stage | Controlled traces show visible correspondence between rate changes and WeMo on/off transitions, Echo questions, Sense sleep changes, Nest live streaming, and Nest motion events | Demonstrated through device-specific case studies, not a unified user-activity classifier | Not a monitoring-system benchmark | Internet blocking leaves 4 devices with limited functionality and 3 with none; ILP masking requires at most 7.5 KB/s for non-audio/video devices and no more than 40 KB/s for audio/video households in the authors' experiments | Strong feasibility evidence, but not directly comparable to the multi-class classifier scores in the other papers |
| **HomeSnitch** | Assumes or separately determines IoT device identity; classifier output includes vendor and model in the behavior triple | Not framed as a separate task | Random Forest on YourThings: accuracy 99.69% ± 0.06, recall 94.66% ± 1.21, F1 93.93% ± 1.40. kNN: accuracy 99.32% ± 0.12, recall 87.97% ± 2.16, F1 86.35% ± 2.56. Gradient Boost performs poorly and unstably. | Not designed for human-activity sequence inference | Approx. 100 ms controller-related latency overhead; retains 97.01% throughput relative to baseline in the reported test | SDN policies successfully block selected uploads. Ring Doorbell test drops 407 packets / 31,462 bytes; D-Link motion-sensor test drops 26 packets / 1,936 bytes, but the sensor uploads buffered events after policy expiry | Excellent semantic-flow classification does not mean it reconstructs composite human behavior; buffered retransmission can undermine policy intent |
| **Peek-a-Boo** | Stage 1 ZigBee identification: 93% overall accuracy with kNN. WiFi and BLE identification are supported by prior literature rather than reimplemented as the same experiment. | Stage 2 average F1: Random Forest 88%, kNN 91%. Reported average accuracy: Random Forest 99%, kNN 95%, although the class imbalance makes F1 more informative. | Stage 3 Random Forest: 92% F1 in 5-fold CV; held-out precision 96%, recall 94%, F1 94% over 126 unseen samples | HMM: Activity 1 = 100% accuracy / F1; Activity 2 = 100% / 100%; Activity 3 = 100% / 100%; Activity 4 = 95% / 95%; Activity 5 = 93% / 91%; Activity 6 = 94% / 94% | Offline analysis; no deployed end-to-end runtime measurement | False-data injection: 10% falsified traffic reduces stage-2 score by 13%; at 90% false addition, device-state detection falls by about 57%; state-classification F1 reaches 15% at 90% injected false data | The authors explicitly note that true end-to-end success depends on multiplying stage-level success probabilities, but a complete propagated attack score is not reported |

### 5.2 Peek-a-Boo stage-4 activity labels

| Activity ID | Description | Accuracy | F1 score |
|---|---|---:|---:|
| Activity 1 | User controls a device from inside the smart-home environment | 100% | 100% |
| Activity 2 | User controls a device from outside the smart-home environment | 100% | 100% |
| Activity 3 | User performs tasks from a specific point inside the home | 100% | 100% |
| Activity 4 | User walks from one point to another inside the home | 95% | 95% |
| Activity 5 | User enters or exits the smart-home environment | 93% | 91% |
| Activity 6 | User opens or closes a window or door | 94% | 94% |

### 5.3 HomeSnitch algorithm comparison

| Model | Accuracy | Recall | F1 score |
|---|---:|---:|---:|
| k-Nearest Neighbor | 99.32% ± 0.12 | 87.97% ± 2.16 | 86.35% ± 2.56 |
| Gradient Boost | 64.70% ± 42.10 | 53.55% ± 33.51 | 51.72% ± 32.72 |
| Random Forest | 99.69% ± 0.06 | 94.66% ± 1.21 | 93.93% ± 1.40 |

### 5.4 Spying on the Smart Home traffic-shaping thresholds

| Device | Shaped upload rate | Shaped download rate | Average per-packet latency | Maximum per-packet latency | Observed behavior at threshold |
|---|---:|---:|---:|---:|---|
| Amazon Echo | 10 KB/s | 10 KB/s | 0.9 s | 4.4 s | Answers questions with several seconds of delay; slower shaping interrupts answers |
| Belkin WeMo Switch | 5.0 KB/s | 2.5 KB/s | 1.3 s | 2.6 s | Works with a few seconds of switching delay; slower shaping causes app connection loss |
| Orvibo Smart Socket | 0.25 KB/s | 0.25 KB/s | 0.8 s | 2.6 s | Works with delay; slower shaping can falsely report success without changing socket state |
| TP-Link Smart Plug | 0.5 KB/s | 0.5 KB/s | 0.8 s | 1.7 s | Works with delay; slower shaping makes plug unreachable |
| Nest Security Camera | 10 KB/s | 10 KB/s | 8.5 s | 17.6 s | Streams video with 10–15 seconds of lag; slower shaping loses connection |
| Amcrest Security Camera | 35 KB/s | 2.5 KB/s | 1.5 s | 3.4 s | Streams with approximately one-minute delay; slower shaping increases lag and reduces reliability |
| Sense Sleep Monitor | 2.5 KB/s | 2.5 KB/s | 0.4 s | 1.4 s | App receives live updates; slower shaping stops live updates |

---

## 6. Defense and enforcement comparison

| Paper | Goal of mitigation | Mechanism | Deployment point | What it protects against | Quantified result | Cost or trade-off | Evaluation maturity |
|---|---|---|---|---|---|---|---|
| **Spying on the Smart Home** | Hide activity-correlated traffic-rate metadata from upstream observers | VPN plus ILP traffic shaping; fixed-size packets; queue real traffic; inject cover traffic; use Linux `tc`, priority queuing, and hierarchical token bucket; simulate or recommend variable-interval timing to reduce jitter leakage | Home router / hub and VPN endpoint outside adversary's last-mile view | ISP-like traffic-rate analysis and device-level metadata leakage | Up to 7.5 KB/s cover traffic for non-audio/video homes; no more than 40 KB/s for audio/video homes; approximately 19 GB/month and 104 GB/month respectively in worst-case accounting | Bandwidth overhead, data usage, added latency, VPN trust, and dependence on upstream position | Strongest defense evaluation of the three: implemented, measured per device, and discussed at deployment level |
| **HomeSnitch** | Detect, report, and control semantically undesirable device behavior | SDN behavior-aware policy actions: alert, log, pass, drop, reject, redirect; context includes time, encryption state, and management-device presence | Consumer router with OpenFlow and Ryu controller | Known privacy-invasive or malicious flows, such as motion upload or firmware download | Demonstrated blocking of Ring Doorbell motion-upload packets and D-Link motion-sensor uploads; malicious TP-Link firmware-download attempts are detected and logged | Depends on historical flow associations and device buffering behavior; first unseen malicious behavior may not be preempted; full-flow classification delays precise decisions | Strong prototype, but behavior-control semantics are device-specific and can be undermined by deferred uploads or mimicry |
| **Peek-a-Boo** | Reduce the attacker's ability to detect device transitions and classify events | Generate spoofed packets or false activity traffic; experiments inject falsified data into feature vectors / datasets; paper discusses app-based advertising or status requests | Smart-home apps or open ecosystems such as SmartThings | Local eavesdropper's state-detection and state-classification stages | Stage-2 score declines with false traffic; stage-3 F1 reportedly falls to 15% at 90% false-data injection | Potential bandwidth, latency, implementation complexity, and risk that cover traffic is itself distinguishable; these are not fully quantified | Early-stage mitigation concept; not validated as an end-to-end deployed online defense |

### Defense-selection implication

The defense mechanisms are not substitutes:

- Use **Spying on the Smart Home's ILP shaping** when the goal is to hide aggregate activity metadata from an upstream observer.
- Use **HomeSnitch's SDN enforcement** when the goal is to detect and block known semantic behaviors at the home router.
- Treat **Peek-a-Boo's spoofed traffic** as an attack-disruption research direction, not as a deployment-ready defense.

A stronger system could combine ILP shaping for upstream privacy with behavior-aware router policy for local control.

---

## 7. Visual workflow comparison

The diagrams in the papers clarify their different abstractions:

| Paper | Figure and location | What the visual emphasizes | Why it matters |
|---|---|---|---|
| **Spying on the Smart Home** | Figure 5, page 7; Figure 8, page 10; Figure 9, page 12 | Figure 5 shows visible traffic-rate spikes corresponding to user actions. Figure 8 shows the router-side traffic-shaping queue and token-bucket design. Figure 9 quantifies the per-device latency and shaping thresholds. | The paper's logic is intentionally simple: if user actions visibly perturb rate, mask rate. |
| **HomeSnitch** | Figure 2, page 3; Table 1, page 4 | The SDN control plane contains a behavior classifier, context monitor, and policy enforcer. Table 1 defines the 13 ADU dialogue features. | The system is a semantic control layer, not merely an attack demonstration. |
| **Peek-a-Boo** | Figure 2, page 4; Figure 3, page 7; Figure 4, page 9; Figure 6, page 12 | Figure 2 presents the four-stage attack cascade. Figure 3 models a user walking through a home as a sequence of device-state changes. Figure 4 shows degradation after false-data injection. Figure 6 shows visible rate peaks for WiFi, ZigBee, and BLE devices. | The contribution is the composition of multiple inference levels across heterogeneous wireless protocols. |

---

## 8. Paper-by-paper analysis

## 8.1 Spying on the Smart Home

### Problem

The paper argues that encrypting payloads is insufficient because traffic metadata still correlates with device state and user behavior. A passive network observer can identify devices and infer activities without reading application content.

### Attack flow

1. Identify the device using MAC organizational identifiers where LAN access exists, DNS queries where available, or traffic-rate fingerprints.
2. Associate traffic-rate changes with device states and human activity.
3. Use knowledge of single-purpose IoT devices to interpret the state transition.

The key insight is that many IoT devices have a narrow set of functions. Once the observer knows a flow belongs to a switch, camera, sleep monitor, or assistant, a rate change is easier to interpret than a comparable change in general-purpose computer traffic.

### Strengths

- The ISP-like vantage point is consequential: the attack may use data that network operators already collect.
- The paper shows the limitation of simplistic defenses. Blocking Internet traffic makes many devices partly or entirely unusable. A VPN aggregates flows, but it does not guarantee privacy when one device dominates traffic, activities are sparse, or only one relevant device is active.
- The traffic-shaping defense is unusually concrete. It is implemented on a Raspberry Pi router, paired with an OpenVPN endpoint, measured per device, and discussed in terms of bandwidth, data caps, and latency.

### Weaknesses

- The attack experiments are intentionally small and illustrative. They establish risk but do not evaluate a general multi-device activity classifier with realistic household interference.
- The device-identification proof of concept uses only two traffic-rate features and six devices.
- The shaping-cost discussion is sensitive to the household's network constraints, device mix, and VPN trust model.
- Constant-rate shaping is vulnerable to small timing deviations caused by system jitter. The paper addresses this by recommending variable-interval timing and simulating it, but the production implementation remains a design consideration rather than a complete deployment result.

### Best use in a new project

Use this paper as the baseline for:
- WAN / ISP threat modeling;
- a minimal traffic-rate fingerprinting prototype;
- a router-based ILP defense;
- experiments comparing blocking, VPN-only tunneling, and VPN-plus-shaping.

---

## 8.2 HomeSnitch

### Problem

HomeSnitch addresses a different question: can a defender make encrypted IoT traffic understandable and controllable at the home router? The objective is to identify semantic device behavior despite proprietary protocols and encryption, then enforce user policy.

### Pipeline

1. Observe an IP connection-oriented flow.
2. Use `adudump` to reconstruct application data units from TCP/IP packet headers without payload inspection.
3. Compute 13 features summarizing client/server dialogue throughput, burstiness, synchronicity, and duration.
4. Classify the ADU into a behavior triple: `<vendor, model, activity>`.
5. If the confidence score is low, report an unknown behavior and nearby matches.
6. Feed behavior and context into an SDN policy engine that can alert, log, pass, drop, reject, or redirect traffic.

### Strengths

- The paper uses an independent corpus for its primary evaluation rather than only self-collected traces.
- Features are destination-agnostic and content-agnostic. Excluding IP addresses, ports, and DNS reduces dependence on brittle infrastructure details.
- The behavior-level abstraction is materially more useful for a user than raw flow labels.
- The paper evaluates unknown behaviors rather than forcing every sample into a known class.
- The implementation is substantial: Linksys router, custom OpenWrt firmware, Open vSwitch, Ryu controller, Raspberry Pi 3, and 6,503 lines of Python.
- It evaluates more than model accuracy: network performance, sample requirements, a 20-device deployment, malicious firmware-download detection, and policy enforcement.

### Weaknesses

- The behavior triple is vendor- and model-specific. A Ring Doorbell model mismatch causes classification difficulty, showing that hardware revisions and firmware changes can undermine portability.
- Semantic labels in the home deployment require manual interpretation.
- Precise classification requires the complete flow. That creates tension with immediate prevention: the first occurrence of an unseen behavior may finish before it is fully classified.
- Policy outcomes depend on device buffering. Blocking a D-Link motion upload temporarily does not erase the event; the sensor uploads buffered data when the policy expires.
- Mimicry attacks are explicitly out of scope.
- Non-IP protocols such as ZigBee and Bluetooth are explicitly left for future work.

### Best use in a new project

Use this paper as the baseline for:
- semantic classification of encrypted IoT flows;
- ADU extraction pipelines;
- behavior-aware router monitoring;
- unknown-behavior detection;
- policy enforcement experiments;
- studying model drift across firmware and hardware versions.

---

## 8.3 Peek-a-Boo

### Problem

Peek-a-Boo asks whether a local passive attacker can automate increasingly sensitive inferences from heterogeneous smart-home traffic. Its novelty is the cascade from device-level metadata to user-level activity.

### Four-stage pipeline

1. **Device identification**  
   Identify the smart-home device type. The paper reimplements a kNN identification experiment for ZigBee devices using interval-level traffic statistics and relies on existing literature for WiFi and BLE identification feasibility.

2. **Device-state detection**  
   Decide whether an interaction or state transition occurred. Divide packet sequences into windows and classify activity versus inactivity from packet-length and timing statistics.

3. **Device-state classification**  
   Decide which specific state or action occurred, such as on versus off or locked versus unlocked. Extract 795 automated time-series features with `tsfresh`, reduce to 197 features using Extra Trees importance, and compare multiple classifiers. Random Forest performs best.

4. **User-activity inference**  
   Combine device states, sensor states, timing, controller state, and controller location into an HMM. Infer higher-level activities such as walking through the home, entering/exiting, or opening/closing a door.

### Strengths

- It explicitly separates device event inference from composite user-activity inference.
- It spans WiFi, ZigBee, and BLE, unlike HomeSnitch's IP-focused scope.
- Its collection design includes both controlled actions and uncontrolled simultaneous-device periods with background traffic.
- The stage-4 HMM is a meaningful attempt to model temporal sequences rather than isolated flow labels.
- The paper acknowledges an important issue that is often hidden: an end-to-end cascade succeeds only when all stages succeed.

### Weaknesses and replication warnings

1. **No single end-to-end score**  
   The paper reports strong scores for individual stages, but not the final probability that the entire cascade infers a user activity correctly. The authors state that the probabilities multiply across stages. This is a substantial distinction because a cascade with individually strong stages can still lose accuracy end to end.

2. **Stage-1 scope is narrower than the overall claim**  
   The paper experimentally reimplements ZigBee identification while citing prior work for WiFi and BLE. Its broad protocol coverage is real at the dataset and case-study level, but the same unified identification method is not independently validated across every protocol.

3. **Mitigation is not a full deployment evaluation**  
   The false-data defense modifies feature vectors / training data and discusses how apps might generate spoofed traffic. It does not quantify a deployed online defense's bandwidth, latency, detectability, or operational failure modes.

4. **User-count inconsistency**  
   The stage-4 description states that network traffic data were collected from 10 users, while the results section states that training data came from 15 people with 30 datasets. The paper does not reconcile these statements.

5. **Printed F1-score formula error**  
   Appendix A prints an F1-score equation that incorrectly includes true negatives: `2 * TP * TN / (TP + TN)`. The standard F1 score is based on precision and recall, or equivalently `2TP / (2TP + FP + FN)`. The reported tables may still have been computed correctly in code, but a replication should recompute every metric from confusion matrices instead of copying the printed equation.

6. **Generalization assumption**  
   The attack assumes access to matching brand and device type during training. The paper itself notes that testing across brands, models, firmware versions, and configurations remains future work.

### Best use in a new project

Use this paper as the baseline for:
- end-to-end multi-stage activity inference;
- local wireless eavesdropping threat models;
- mixed WiFi / ZigBee / BLE experiments;
- temporal inference with HMMs or modern sequence models;
- evaluating how background traffic and multi-user activity degrade inference.

---

## 9. Why the reported accuracy values are not directly comparable

| Difference | Spying on the Smart Home | HomeSnitch | Peek-a-Boo |
|---|---|---|---|
| Prediction target | Device identity and visible activity-correlated rate changes | Semantic flow behavior triple | Device identity, transition detection, specific state, and composite user activity |
| Evaluation sample | Time window and controlled trace segment | ADU / connection-level dialogue | Interval window, time-series vector, or HMM sequence depending on stage |
| Dataset | Small self-collected laboratory setup | Independent 46-device corpus plus residential deployment | Self-collected 22-device traces plus separate activity environment |
| Background interference | Limited in proof-of-concept fingerprinting | Present in home deployment | Explicit controlled plus uncontrolled background collection |
| Headline number | Greater than 95% device fingerprinting accuracy | 99.69% behavior classification accuracy | Greater than 90% stage-level results; stage-specific metrics |
| End-to-end user-activity inference | Case-study demonstration | Not the objective | Intended objective, but full propagated success rate not reported |

A valid benchmark comparison would require all three approaches to be rerun on the same packet captures, labels, train/test splits, and adversary-visible metadata.

---

## 10. Replication-oriented decision guide

| Research objective | Recommended starting paper | Reason | Main adaptation needed |
|---|---|---|---|
| Build a simple proof that encrypted IoT traffic leaks behavior | **Spying on the Smart Home** | Small feature set and straightforward rate plots make the core leak easy to reproduce | Capture PCAPs, map devices, bin byte counts over time, and reproduce device-specific controlled actions |
| Use an independent corpus rather than collecting all traffic yourself | **HomeSnitch** | Explicitly evaluates on the independent YourThings dataset | Verify current corpus access; implement ADU extraction; recreate labels and splits carefully |
| Build a router-side semantic monitor | **HomeSnitch** | Most complete network-defense architecture | Reproduce `adudump`-equivalent ADU extraction and SDN integration; account for full-flow latency |
| Defend against an ISP-like traffic observer | **Spying on the Smart Home** | Directly evaluates VPN limitations and ILP shaping | Implement VPN endpoint and Linux traffic shaping; test modern household traffic and network constraints |
| Infer composite human activities from several devices | **Peek-a-Boo** | Only paper among the three with an explicit multi-stage HMM activity layer | Collect synchronized labeled device/sensor traces; report propagated end-to-end metrics; resolve multi-user ambiguity |
| Study protocol diversity beyond IP | **Peek-a-Boo** | Covers WiFi, ZigBee, and BLE | Build protocol-specific sniffing and timestamp normalization; test whether one model family generalizes across protocols |
| Detect new or unexpected device behaviors | **HomeSnitch** | Explicitly models unknown behaviors with confidence thresholds | Evaluate calibration, model drift, and false-alert burden over long deployments |
| Evaluate cover-traffic defenses | **Spying on the Smart Home** first, then **Peek-a-Boo** | Spying provides a deployable ILP baseline; Peek-a-Boo motivates event-specific spoofing | Compare constant-rate shaping, variable-interval shaping, adaptive cover traffic, and distinguishability of synthetic packets |

---

## 11. Reproducibility assessment

| Paper | Reproducibility strengths | Reproducibility weaknesses | Practical replication difficulty |
|---|---|---|---|
| **Spying on the Smart Home** | Clear device list, router setup, feature construction, controlled actions, and shaping design; traffic-shaping script described as fewer than 100 lines | PDF does not provide a repository link for traces or code; exact packet-processing scripts and labeled captures are not included | **Low to medium** for reproducing the core leak; **medium** for a rigorous ILP evaluation |
| **HomeSnitch** | Detailed architecture, 13 named features, model comparison, independent dataset description, performance measurements, and policy examples | PDF does not provide a HomeSnitch repository link; depends on `adudump`; behavior labels and empirical clustering procedure require interpretation; `adudump` availability must be resolved separately | **Medium to high** |
| **Peek-a-Boo** | Detailed stage structure, feature families, classifier comparison, device list, collection strategy, and stage metrics | No dataset or full-code release link in the PDF; multiple stages and separate datasets; user-count inconsistency; printed F1 formula error; defense not deployed end to end | **High** |

### Reproducibility conclusion

For a clean first implementation, start with **Spying on the Smart Home**. For a publishable semantic-flow system, build from **HomeSnitch**. For a full research replication of user activity inference, treat **Peek-a-Boo** as a design specification that requires substantial independent engineering and validation rather than as a turnkey reproducible pipeline.

---

## 12. Recommended unified research pipeline

A stronger follow-up system could combine the best parts of all three papers:

| Pipeline layer | Recommended source idea | Proposed implementation |
|---|---|---|
| Capture | Peek-a-Boo plus Spying | Collect synchronized WAN and local wireless traffic across WiFi, ZigBee, and BLE; preserve the exact attacker-visible metadata at each vantage point |
| Normalization | Peek-a-Boo | Convert packet traces into a common timestamp, direction, and length representation; maintain protocol-specific identifiers separately |
| Flow / dialogue extraction | HomeSnitch | Build ADU-like dialogue representations for IP traffic and analogous exchange abstractions for ZigBee and BLE |
| Simple baseline | Spying | Start with traffic-rate bins, mean, and standard deviation so the privacy leak remains interpretable |
| Semantic device-event model | HomeSnitch plus Peek-a-Boo | Compare ADU Random Forest baselines against time-series and sequence models; calibrate unknown-event detection |
| Composite activity model | Peek-a-Boo | Use temporally ordered device-event predictions as input to HMM, conditional random field, recurrent network, or transformer baselines |
| End-to-end evaluation | Missing from Peek-a-Boo | Report both stage-level metrics and final propagated user-activity metrics under background traffic, multiple residents, firmware drift, and unseen devices |
| Defense baseline | Spying | Implement VPN plus ILP shaping and variable-interval timing |
| Adaptive defense | Peek-a-Boo plus HomeSnitch | Add behavior-aware or event-aware cover traffic, but explicitly test whether synthetic traffic is distinguishable and quantify bandwidth / latency costs |
| Enforcement | HomeSnitch | Add router policy for known privacy-invasive behaviors and measure whether buffering, retries, and mimicry defeat the policy |

---

## 13. Research gaps exposed by the comparison

| Gap | Why it matters | Best starting point |
|---|---|---|
| True end-to-end activity inference under realistic household interference | Stage-level accuracy can overstate the attacker's actual success | Peek-a-Boo |
| Multi-user homes | Concurrent human actions create ambiguity and false correlations | Peek-a-Boo discussion section |
| Cross-firmware and cross-model drift | Device updates can invalidate behavior fingerprints | HomeSnitch Ring Doorbell mismatch |
| Unified WiFi, ZigBee, and BLE representation | Protocol-specific metadata visibility differs substantially | Peek-a-Boo |
| Unknown behavior calibration over time | A low threshold can flood users with alerts; a high threshold misses new behaviors | HomeSnitch |
| First-occurrence prevention | Full-flow classification may detect a malicious behavior only after it completes | HomeSnitch |
| Device buffering and delayed exfiltration | Temporarily blocked events may upload later | HomeSnitch D-Link policy experiment |
| Cover-traffic distinguishability | Synthetic traffic can become another fingerprint if generated naively | Peek-a-Boo mitigation concept |
| Cost-aware privacy defense | ILP is effective but consumes bandwidth and introduces latency | Spying on the Smart Home |
| Comparable benchmarks | Current headline accuracy values evaluate different tasks and cannot establish which approach is superior | All three |

---

## 14. Template for adding another paper

Copy this row into each relevant comparison table and fill in the cells.

| Paper | Year / venue | Primary objective | Perspective | Main observer or deployment vantage point | Protocol scope | Unit of analysis | Core technique | Primary output | Dataset scale | Headline results | Proposed defense or enforcement | Strongest contribution | Most important limitation |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **New paper title** |  |  |  |  |  |  |  |  |  |  |  |  |  |

---

## 15. Source map

| Paper | Most relevant sections for this report |
|---|---|
| **Spying on the Smart Home: Privacy Attacks and Defenses on Encrypted IoT Traffic** | Abstract; §3 Threat Model; §4 Experiment Setup; §5 Traffic Rate Privacy Attack; §6 Evaluating Current Defenses; §7 Traffic Shaping; §8 Discussion |
| **HomeSnitch: Behavior Transparency and Control for Smart Home IoT Devices** | Abstract; §2 Motivation and Problem; §3 Overview; §4 Design; §5 Implementation; §6 Evaluation; §7 Empirical Study; §8 Limitations |
| **Peek-a-Boo: I see your smart home activities, even encrypted!** | Abstract; §2 Adversary Model; §4 Multi-Stage Privacy Attack; §5 Mitigating the Privacy Leaks; §6 Discussion; Appendix A Performance Metrics; Appendix B Case Studies |

---

## 16. Final assessment

The papers should not be treated as three implementations of the same classifier.

- **Spying on the Smart Home** is the strongest foundation for understanding and mitigating WAN-visible traffic-rate leakage.
- **HomeSnitch** is the strongest system paper for semantic encrypted-flow classification and router-level policy enforcement.
- **Peek-a-Boo** is the strongest attack blueprint for reconstructing user activity from heterogeneous local wireless metadata, but it requires the most careful independent replication.

For a new research project, the most defensible design is to use **Spying on the Smart Home** as the interpretable traffic-rate baseline, **HomeSnitch** as the semantic ADU baseline, and **Peek-a-Boo** as the end-to-end activity-inference target. Evaluate them on one synchronized dataset and report a separate score for each layer rather than collapsing the system into a single headline metric.
