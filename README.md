# Introduction
This reposistory contains the code for the tool presented in the paper *Network trace generation for flow-based IDS evaluation in control and automation systems*
It is split in three main directory
- Analysis : Which contains all the code used to analyze PCAP files. All those scripts are used to provide flow information about a network dataset.
- Generator : Which contains all the code to generate dataset from an input network trace. The idea is to extract flow information and replay the flow in an emulated network. The generator allows to inject network attack during the replay of the network such that the generated dataset can be used to evaluate IDS. This repository contains several IDS that were evaluated in such a way.
- Evaluation : Which contains some utility code. The tool split the input dataset into frame of user-defined duration. For each frame, the tool extracts the flows information and during the generation, it will iterate over the frame and replay what is has seen while including attack traffic if necessary.

# Usage

## Requirements
This tool needs the following packages:
- ipaddress==1.0.17
- matplotlib==2.2.3
- mininet==2.3.0d4
- numpy==1.16.2
- scikit-learn==0.20.2
- scipy==1.2.0
- ovs==2.10.0
- pyyaml==3.13
- scapy==2.4.2

There are two important file necessary in order to generate new dataset. The FlowExtractor and the FlowHandler.

### FlowExtractor
The FlowExtractor is located in generator/extractor/. There is MAKEFILE to build the flowextract binary. This C program takes 4 arguments and is used in the following way:
```bash
./flowextract -d <INPUT_DIRECTORY> -o <BINARY_OUTPUT_DIRECTORY> -t <TEXT_OUTPUT_DIRECTORY> -s <FRAME_SIZE_IN_SECONDS>
```
- INPUT_DIRECTORY: This is the directory where the pcaps files are located.
- BINARY_OUTPUT_DIRECTORY: This is the directory where specific-formatted binary files are written. The number of files written depends on the size of a frame.
- TEXT_OUTPUT_DIRECTORY: This is the directory where specific-formatted text files are written. The number of files written depends on the size of a frame.
- FRAME_SIZE_IN_SECONDS: This duration of a frame in size.

### FlowHandler
The FlowHandler is located in generator/handlers. This python program takes several argument but the most important on is a configuration that is used for managing the generation process.
During the generation process, a network is emulated, meaning virtual hosts are created and they exchange packets. Those packets are captured via tcpdump.

This configuration file, which is a yaml file as the following fields:
- input: The directory where to find the flow information, frame by frame. It is the same input directory as the one given as output for the text.
- output: The directory where to write the new traces.
- mappingIP: the name the file were to write the mapping between the original IP addresses and the one used in the generation
- safeMode: Attack a new host created only for the generation or a host part of the original dataset
- attackFrame: Number of the frame when to perform the attacks
- attackDir: Directory where to fine the ressources to perform the attacks
- attack: Command-line to run the attacks
- application : list of well-known ports to identify Client/Server

With configuration file set, the flowHandler can be run as follow
```bash
python flowHandler.py --conf <CONFIG_FILE> --mode <MODE> --read <READTYPE>
```
- CONFIG_FILE: The path to the configuration file
- MODE : The mode used for the generation. It can be either mininet or local. With mininet, a network will be emulated using Mininet. With local, packets are exchanged on the local interface.
- READTYPE: Format expected for the file in the input directory, either bin (for binary) or text.
