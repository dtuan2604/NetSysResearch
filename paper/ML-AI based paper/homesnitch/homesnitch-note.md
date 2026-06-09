# Introduction
- The key insight is to classify and control *semantic behavior* using features that represent application-layer dialogue between clients and servers
- HomeSnitch is implemented on a commodity wireless router and build upon **Software Defined Networking**
- The paper propose a **supervised learning technique** to classify semantic device behaviors using network traffic
- Perform empirical evaluation of HomeSnitch in a real home environment

# Motivation and Problem
- To achieve the goal, HomeSnitch <mark>operate on application behaviors</mark> such as heartbeat, firmware checks, reporting, and uploading audio or video recording
    - Abstracting network flows and packet data into classifications offers better intuition about the device activity
- HomeSnitch seesk to report <mark>**which** device perform **what** behaviors, **when** and **how often**</mark>, rather than simple existence and frequency of network traffic
- Threat model: can be found in the paper as the author provide a pretty comprehensive description

# Architecture (Overview)
- Figure 1 in the paper show the high level architecture
- When devices communicate with *servers*, or with another on *LAN*, HomeSnitch classifies the network flows as **known behaviors** for device. **Unknown network flows** are matched with a set of the closest behaviors and reported to serivce provider to enhance training models
- <mark>Paper claims to address 2 problems</mark>:
    - Behaviors Classification: Large gap between bytes sent in packets and behaviors that are understandable to users.
    - Network Mediation: **Not sure what the problem here is** 
- To overcome these problems, they use **SDN** and **supervised machine learning**

# Design
## Classification of Application Behaviors
- <mark>To overcome **encrypted traffic**, HomeSnitch constructs ADU exchanges that provide an abstract representation model of the exchange between a client and a server</mark>
    - They use <mark>*adudump*</mark> for this
    - *adudump* only uses TCP/IP packet header traces

### Feature Selection
- Selected 13 features from transport layer headers
    - Each feature is calculated from a single application data unit (ADU). 
        - ADUs are bidirectional representations of sequential exchanges within a single connection. terminated upon proper connection tear-down or by flow timeout
- Exclude **IP address**, **port number**, and **DNS** information because they present *limitation* and **less reliable**
- Focus on **content agnostic** features
- They also focus on the importance of features describing **burstiness**, **synchronicity**, and **throughput** of application dialogue
- Set of features mentioned in Table 1 in the paper
- Feature definition:
    - **sequence**: indicates a single directional application exchange
    - **ADU**: indicates the entire application data unit dialogue, bounded by the creation and termination of the entire network flow;
    - **burstiness**: describes the proximity of arrival instances within each other and the variance between each arrival
        - The *variance* is examined in terms of both <mark>payload size</mark> and <mark>inter-arrival times</mark>
    - **synchronicity**: describe how a client and server take turns sending data within the context of an ADU
    - **throughput**: a routinely used and important measure of the aggregate data sent over the duration of the ADU
- Feature importance are calculated and shown in Table 1
    - *average bytes*, *max bytes*, and *aggregate bytes* were the most dominant features and accounted for 46.65%
        - The reason is because smart home devices are typically designed for specific purposes and communicate in a limited fashion
- What they observe:
    - ***burstiness* feature**: describe <mark>on-demand actions of motion sensors</mark>
    - ***throughput* features**: describe <mark>data-intensive sensors</mark>
    - ***synchronicity and duration* features**: strong features for <mark>data logging and analytic report</mark>
    
### Model Selection
- <mark>Random Forest</mark> to be the best for **intuitive** reasons. Because:
    - It leverages both **ensemble** and **averaging** methods to build several estimators **independently** and then average their prediction. By leveraging a bagging-based ensemble model, HomeSnitch is **resistant** to **under-fitting** with a reduced variance.
    - Second reason is that HomeSnitch needs to inform the user when previously unseen behavior occur
        - An ensemble or averaging based classifier would be more resistant to under-fitting, which make it more suitable for detect unknown behavior with the closest distance to the known behavior
- *Unknown Behavior Miss Rate* (UBMR): percentage of data-points in a given data-set that fail to be identified as a new classification
    - Ideally, classification model should minimize UBMR without adverse affect to the TPR (True Positive Rate)
    - They found the threshold of 0.89% as the best balance between UBMR and TPR

### Training Data
- Two approaches to construct the intial training data:
    - First:  Construct initial labels from a corpus of time-stamped behaviors -> Does not scale well
    - Second: Use clustering algorithm to identify behavior classes in spatial data-sets. Specifically, use the density sampling algorithm DBSCAN

### Security Service Provider
- Trained model is often specific to devices by the same manufacturer
- The paper propose <mark>the use of a security service provider (SSP)</mark> to share features and expand the set of supported smart home device behaviors
    - This allows the development of a model that expands as the heterogeneity of devices increases
- HomeSnitch can also use a **publish-subscribe** interface similar to virus reporting

### Behavior Reporting
- HomeSnitch offers novel behavior detection and descriptive reporting

## Context Monitor
- Archive historical flow data in a database at the controller

# My Stimulation Experiment
## What is *adudump* and how to use it?
- Paper developing *adudump*: [Passive, Streaming Inference of TCP Connection Structure for Network Server Management](https://www.cs.unc.edu/~jeffay/papers/TMA-09.pdf)
