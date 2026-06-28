# June 26th, 2026
## MAC address observation
- Sniffing 802.11 connection gives you frame package. I can only see the MAC address and other frame level and layer-2 looking like information
    - I do not see anything useful but the MAC address, and frame size
    - Anything from layer 3 onward are WPA/WPA2 encrypted. No access.
- MAC address: 
    - The first 6 hexadecimal digits identify the **manufacturer**, called the OUI (Organizational Unique Identifier). IEEE Registration Authority assigns these MAC prefixes to its registered vendors.

![Sniffing experiment](./imgs/screenshots/sniffing-experiment.png)

- Looking into the MAC address used in both dataset, these are my observations:
    - Occasionally, devices belong to the same vendor have the same first 6 MAC digits i.e:
        - Withings:
            - Smart Baby Monitor
            - Smart Scale
            - Smart Sleep Sensor
        - Geeni
            - Camera 2
            - Camera 3
        - NEST
            - Smoke alarm
            - Camera
        - Netatmo
            - Welcome
            - Weather Station
        - Belkin Wemo
            - Switch
            - Motion Sensor
- Based on my observation, it is very likely that the OUI can be used to uniquely identify *\<device, vendor\>* tuple
- Occasionally, some of different devices belong to the same vendor also share OUI tuple
- However, there are also edge cases where devices belongs to the same vendor, even the same type, have different OUI. 
- <mark>TO-DO</marj>:
    - Research to see if OUI can be used to uniquely identify *\<device, vendor\>*
    - On layer 2, we can only see MAC address, probably try ML on packet length, direction, potentially inter-arrival time if we can use that to identify anything

## References
- [What is MAC Address?](https://www.geeksforgeeks.org/computer-networks/mac-address-in-computer-network/)