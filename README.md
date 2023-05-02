# SDM-assignment
Solution to the group project of the Secure Data Management course at the University of Twente. The assignment was to implement a searchable encryption scheme that:
- allows a consultant to insert data for all of this clients in the storage server
- allows the consultant to search for specific information for any specific client through the encrypted data on the storage server
- allows a client to insert data in (only) his own encrypted record on the storage server
- allows a client to search for specific data in (only) his own record on the storage server

The main branch implements the Song-Wagner-Perrig searchable encryption scheme. The InvertedIndex branch implements the Dynamic Inverted Index (Kamara et al., 2012) scheme. The latter is not comletely finished (e.g. deletion is not working).

Not that the given code is not validated, and only serves as a prototype. This code should never be used in real applications as-is.

![image](https://user-images.githubusercontent.com/52708576/235623916-8157df00-a9d3-42b4-adf1-c8f08191c264.png)
