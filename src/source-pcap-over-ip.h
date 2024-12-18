#ifndef SURICATA_SOURCE_PCAP_OVER_IP_H
#define SURICATA_SOURCE_PCAP_OVER_IP_H

/**
 * Functions to register the packet acquisition and decoding modules.
 */
void TmModuleReceivePcapOverIPRegister(void);
void TmModuleDecodePcapOverIPRegister(void);

#endif /* SURICATA_SOURCE_PCAP_OVER_IP_H */

