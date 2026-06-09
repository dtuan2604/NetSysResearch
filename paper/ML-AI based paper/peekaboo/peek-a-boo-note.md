# Introduction
- Normally, statistical techniques is hard to apply because:
    - Targeted device population is much more heterogenous and uses different network protocols and potentially proprietary application protocols.
    <mark>-> This would extend the potential attack surface, but also makes it harder to devise generic attacks or countermeasures.</mark>
    - There's a need to combine partial information gathered from different smart home devices to get a more meaningful picture. This is hard because <mark>attacker must aggregate information about actions over a longer period of time which is only feasible if activity detection and identification can be **automated**</mark>
- The paper present how <mark>machine learning methods based on traffic profiling can be used by an adversary to automatically **identify actions and activities** of the IoT devices and its users in a victim's smart home with very high accuracy
- It is called **multi-stage privacy attack**, achieved by observing **passively** the wireless traffic from the smart home devices. 
- The attack is **device type and protocol agnostic**
    - Easier to apply to a wide range of different IoT devices
    - No need for tedious harvesting of device-type or protocol-specific knowledge
- A **countermeasure** is also introduced based on generating spoofed traffic to hide the real states of targeted IoT devices. 
- The mentioned attack is claimed to be able to find leakage of:
    - type of devices
    - states of devices
    - sensor data
    - on-going user activities
- The problem is tacked this way:
    - First, convert user activity inference on the timing-based network traffic into a cascaded Machine Learning problem
    - Then, exten the attack by modeling the user activities with **Hidden Markov Model (HMM)** 
- Challenges in the domain of IoT: attack surface is naturally extended and comprises a diverse set of devices and sensors

# Adversary Model
- Threat Model:
    - Local adversary
    - <mark>Located **physically** within the wireless range of the targeted user's smart home devices</mark>
        - Attacker can install the sniffers only once and manage them remotely
        - Or they could compromise a device inside the smart home and turn it into a sniffer
    - Essentially, adversary eavesdrop on network communications transmitted by the user's smart home devices. 
- Assumption:
    - Attacker has access to the same kind of smart home devices and sensors as the targeted user so that it can collect the traffic and use the collected data to train the model
    - Attack has access to protocol headers data on all layers that are not protected by encryption. 
- The paper use *\< brand, device-type \>* to uniquely identify devices

# Features on smart home devices
## Wifi-enabled devices
- Either connected to Internet via Hub-like device or directly connected to an access point
- Both cases, attacker can track and capture traffic through a MAC address
- May want to use IP addresses of servers. However, attack can only see traffic encrypted by SSL/TLS and WPA<
- Prevent attacker from using header-based features for device identification. <mark>However, the traffic rates of devices cannot be hidden</mark>

## ZigBee-enabled devices
- This type of device has two addresses:
    - MAC address
    - Network Address (NwkAddr)
        - Is created and assigned when the device joins a network
        - Changes when it leaves and re-joins anther network
        - Similar to IP, however, it is <mark>not encrypted</mark> which means source and destination of the packets can be seen by the attacker
        - The network coordinator has the <mark>*0x0000*</mark> address and each network has an unique identifier (PAN ID - Persoanl Area Network Identifier)

## BLE-enabled devices
- There are slaves and master nodes
- To connect:
    - Slave broadcasts advertising packets *ADV_IND* randomly on channel 37, 38, and 39
    - Once connection starts, they agree on a channel map and use it for the rest of the communication
- An attacker needs to capture the first packet to learn about channel mapping which it can then used and follow the rest of the communication

# Multi-stage privacy attack
- Consists of four stages
- Every stages leak partial information and can be used independently by the attacker

## Dataset and Evaluation Metric 1
- 22 different smart home devices
- Two stages:
    - Controlled experiment
    - Uncontrolled experiment
- Devices categories include: smart camera, smart locks, lighting, outlets, switches,....
- Efficiency evaluation using:
    - Precision
    - Accuracy
    - Recall
    - F1 Score
    - Support

## Calculating Features
- Before processing, convert packets in traffic flow into a Sequence of Packet Lengths and Times (SPLT) with following format <mark>*pkt = [timestamp, direction, packet length]*</mark>
- Obtaining a matrix with three columns
    - In the feature extraction of each attack, we'll calculate features from this matrix

## Attack Stage 1: Device Identification
- Different works have shown IoT devices with Wifi-enabled and BLE-enabled can be accurately identified. 
- They are using the already existing identification algorithm for Zigbee enabled device, <mark>but with their calculated features</mark>
- Zigbee Hub is not included in the identification process because it can be easily recognized with the defaul network address of *0x0000*
- **Steps**:
    - Collect Zigbee network traffic
    - <mark>Extract features:</mark>
        - Mean packet length
        - Mean inter-arrival time
        - Standard deviation in packet lengths
            - Split each individual network traffic trace of a device into equal time intervals (e.g., 5 sec, 10 sec). Then, calculate these features for each interval.
    - Use kNN classification algorithm
        - Overall accuracy of 93% for Zigbee devices

## Attack Stage 2: Device State Detection
- When a communication occurs, a large amount of data is transmitted -> increase in traffic rate
- After this, it drops to the minimum until a new communication starts
- They observes that almost the same amount of data get transferred for the same activities
- **Steps**:
    - Feature extraction:
        - **Objective**: Transform a sequence of packets into a supervised learning dataset
        - <mark>How?</mark>
            - Divide the sequence of packets into a windows of size $W$
            - For each interval length $W$, extract a feature vector including:
                - mean packet length
                - mean inter-arrival time
                - median absolute deviation of packet size
            - Based on timestamped labels, they labels the vector *1* for an ongoing activity and *0* for no activity
        - <mark>They claim that the **window size** significantly influence their mode's performance. The best window size is about a quarter of the duration of an activity</mark>
    - Two supervised learning algorithms is applied. More granular metrics is in the paper.
        - Random Forest Classifier (RF): 88% F1 average
        - k-Nearest Neighbors Classifier (kNN): 91% F1 average

## Attack Stage 3: Device State Classification
- In this stage, the attacker's goal is to decide the state of the device. This stage is more difficult, however, each state has a unique pattern to differentiate them from each other
- **Steps**:
    - Feature extraction:
        - Features must be extracted from *time-series* generated in the preprocessing steps.
        - *tsfresh* tool is used 
            - This tool automatically calculates time series characteristics and features, then construct feature vector
        - **Example of feature extracted**: Absolute Energy of time-series, Length of time-series, Mean and median of time-series, Skewness of time-series, Entropy of time- series, Standard deviation of time-series, Variance of time-series, Continuous wavelet transform coefficients, Fast Fourier Transform Coefficients, Coefficients of polynomial fitted to time-series.
    - Feature selection:
        - Feature extractions result in 795 binary features -> some of them are redundant and irrelevant which would result in different problems in training
        - A technique leveraging ensembles of randomized decision trees is used to determine features importance
        - Paper use **Extra-Trees Classifier** to compute the relative importance of each attribute
        - Reduce feature vector size from **795** to **197**
    - Training:
        - Use several ML algorithm: XGBoost, Adaboost, Random Forest, SVM with RBF kernel, kNN, Logistic Regression, Naïve Bayes, and Decision Tree
        - 5-fold CV is included in the process
            - 92% F1 is averagely obtained with Random Forest on the training set
            - 94% F1 is measured with Random Forest on the validation set

## Attack Stage 4: User Activity Inference
- **Step**:
    - Model user activity:
        - Including motion sensor ($M$) and light sensor ($L$)
        - Each sub activity is modeled with a sequence of sensor activity. i.e: user opens front door ($L1$, $D1$, $Lo1$ are active)
        - To complete the acitivity, a user <mark>must follow the same sequence of sub-activities</mark> and <mark>complete each step </mark>
    - <mark>Feature extraction:</mark>
        - Extract different features such as timing information, sensor information, device states, location, etc...
        - Inference can be represented as follows: $\text{Data array}, E_T = \{S, D, M, L\}$
            - $T$: timing features extracted from the network traffic
            - $S$: set of sensors' features
            - $D$: set of device features
            - $M$: features extracted from the controlling device
            - $L$: set of location features extraced from the network traffic
    - Hidden Markov Model (HMM) algorithm is used to train to detect user activities
    - Activity Types: 2 categories
        - Time-independent activities
        - Time-dependent activities
        - User activity model is explained as below:
            - User Activity- 1. A user is controlling a device from inside of the smart home environment.
            - User Activity- 2. A user is controlling a device from outside of the smart home environment.
            - User Activity- 3. A user is performing tasks from a specific point of a smart home environment.
            - User Activity- 4. A user is walking from one point to another inside the smart home environment.
            - User Activity- 5. A user is entering/ exiting from the smart home environment.
            - User Activity- 6. A user is opening/ closing a window/ door in smart home environment.
    - Check the comprehensive result report in the paper

# Mitigating the privacy leaks
- **Approach**: generating spoofed traffic to mask the user's absence. Essentially try to falsify the result of device state detection and device activity classification process, which inhenrently render the activity inference process useless
- <mark>The paper discuss the possible improvements</mark>:
    - Paper only analyze the effectiveness of generating spoofed traffic, not actual **defense mechanism**
    - Further defense could include strategy to hide the **location** at home as well as the source and destination of packets to avoid from device state detection and classification attacks

# Discussion
- Possible improvement we can tackle
- **ISP as an adversary**: 
    - Paper has only discussed the local adversary. An extension to this adversary model can be a remote adversary that can monitor outgoing network traffic of the smart home, i.e an ISP. 
    - Advantages:
        - ISP does not have to be within a range
        - It can see source and destination of the packets which a local adversary **can not see if the WPA encryption is enabled**
    - Disadvantage:
        - Can only collect the outgoing network traffic, not the internal two-way
        - An ISP will only see the router's MAC address, **not other smart home devices' MAC address**, for the device identification
            - It can try to use IP with some challenges
- **Multi-user vs single user**:
    - Multiple users performing different activities can create some false positive and false negative
    - However, the attacker can still infer the device type and device state
    - Attacker can also infer the presence of multiple users and the specific point of ongoing activities
    - A single user smart home environment is more vulnerable to the proposed threat
- **Local vs Remote Control**: 
    - The proposed threat model can guess both local and remote access from location feature which is a serious threat to user privacy as attacker can detect when a user is changing the state remotely and perform malicious activities
- **Smart device diversity**:
    - The network protocol and devices diversity make it harder to build a generic solution as well as an attack
- **Generalizability of the attack**: 
    - The attack model assumes that the attacker does not need exactly the same devices to train, but it needs exact brand and device type
    - This assumption, however, **weaken the attack model**. Attacker who can infer the device type and does not need the same device with the same brand would be more realistic

# Related Work
- Identification using the encrypted network traffic
- Fingerprinting methods
- IoT Fingerprinting
- Difference from existing work:
    - This is a comprehensive method of end-to-end attack to infer the on-going user activities, where the previous studies focused on only one stage
    - Proposing the use of HMM where the device activities from multiple devices have been used to infer user activities
    - Perform the experiment with Wifi, Zigbee, and BLE where previous studies have focused only one one of those protocols
    
# What we can do
- Replicate the phase 1 identification with dataset from ping pong and homesnitch
- Do better in MAC address with identification

- Start with looking dataset
- Read homesnitch
- Try experimenting device identification
