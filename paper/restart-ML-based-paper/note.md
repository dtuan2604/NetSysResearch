# 1-A-Smart-Home-Is-No-Castle
- [A Smart Home is No Castle: Privacy Vulnerabilities of Encrypted IoT Traffic](./1-a-smart-home-is-no-castle.pdf)

# 2-Identify-IoT-Devices-And-Events-Based-On-Packet-Length-From-Encrypted-Traffic
- [Identifying IoT devices and events based on packet length from encrypted traffic](./2-identify-iot-devices-and-events-based-on-packet-length-from-encrypted-traffic.pdf)

## Resources
### 1st-resource
- A. Sivanathan, D. Sherratt, H.H. Gharakheili, A. Radford, C. Wijenayake, A. Vishwanath, V. Sivaraman, Characterizing and classifying iot traffic in smart cities and Campuses, in: IEEE INFOCOM Workshop on SmartCity: Smart Cities and Urban Computing, IEEE, Atlanta, GA, USA, 2017, pp. 1–6.
- Paper: [Characterizing and classifying IoT traffic in smart cities and campuses](https://ieeexplore.ieee.org/abstract/document/8116438)
- Dataset: [Data collected for our paper at IEEE TMC 2018](https://iotanalytics.unsw.edu.au/iottraces.html).
    - The original raw IP address for dataset mentioned in the paper is http://149.171.189.1/, but it doesn't work anymore.
    - The dataset include 21 unique IoT devices over 3 weeks.
    - Their ML evaluation uses: 
        - Two weeks of data from 23 Sep - 6 Oct 2016 for training/cross-validation
        - An independent one-week test set from 7-13 Oct 2016 for validation/testing

## Features that they are using for the machine learning approach
- Three traffic attributes are generated from **packet length**.
    - Even though inter-arrival time is also widely used, it is susceptible to network conditions such as congestion. Thus, it would not be considered.
- They propose the use of a **one-second** window to *enable real-time classification*. The following features will be calculated across the window for training and evaluation:
    - **mean**: chosen because it shows a good measure of the central tendency of the length.
    - **standard deviation**: gives variation from the mean.
    - **number of bytes**: shows the fluctuation in the data transmitted by the devices.

## Three-stage process
- Their prototype uses a three-stage process:
    - **Stage 1:** Classify IoT and non-IoT equipment - using binary classifier.
    - **Stage 2:** Classify specific IoT devices - using multi-class classifier.
    - **Stage 3:** Classify events - using multi-class classifier.
- To evaluate the contribution of each statistic to the identification of the devices, Forest of Trees are used.

### Stage 1: Classify IoT and non-IoT equipment
- Data is generated in [1st-resource](#1st-resource)
- Note: For this stage in the dataset, the dataset include MAC and internal LAN IP address to construct label. Even though the technique mentioned in this paper doesn't use those data (only packet length), it still needs a way to *group traffic belong to **each device*** in the one second windows based on the time stamp.
    - This would be easy for threat model listening to traffic within LAN (before NAT) as they have access to internal IP address and MAC address, but not after NAT.
- <mark>TO-DO</mark>: Look into the dataset and the research paper and try to replicate what they did for this stage.
