## What do we do?
With upcoming 5G network architectures in mind, 5G-VCoM exploits a holistic vision of SDN and NFV integration to provide abstract mechanisms that support flow mobility management in an access technology-independent deployment. To this end, 5G-VCoM instantiates a virtual representation of the MN (vMN) and the Point of Attachment (vPoA) in the cloud. These virtual representations can be coupled with the necessary logic to support mobility management entities in the network with the necessary abstract means for heterogeneous cross-technology mobility procedures, whose outcome could be conveyed back to their physical counterparts via SDN signalling extended to the MN.

## Mobile Node and its virtualisation
Selectively using a vMN enables the network to preserve the necessary elements with information about the MN’s medium access to the
network, enabling the Controller to adapt the network building blocks to the different types access technology used by the MN (i.e., mobile and Wi-Fi). 
Notwithstanding, the vMN supports a mobility management cloud service, under which the MN is anchored and mapped in the network. OpenFlow is driven to bind the MN and vMN, enabling both entities to directly interact with each other. While the MN exploits this protocol to provide context about its surrounding wireless links and assist the network connectivity selection, the vMN uses it to manage the data traffic of the MN by implementing flow-level actions.

## Where do we stand?
5G-VCoM is a proof-of-concept framework implemented and evaluated in a physical wireless testbed for abstraction of the mobility procedures in an access technology-independent deployment. The framework virtualizes both PoA and MN and creates the necessary mechanisms allowing those virtual representations to realize mobility procedures in an abstract way. 

# Publications
[1] Flávio Meneses, Daniel Corujo, Carlos Guimarães, Rui L. Aguiar, "An Abstraction Framework for Flow Mobility in Multi-Technology 5G environments using Virtualization and SDN", Proc. 3rd IEEE Conference on Network Softwarization (IEEE NetSoft 2017), Bologna, Italy, Jul 2017
