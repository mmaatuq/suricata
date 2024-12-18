#include "suricata.h"
#include "source-pcap-over-ip.h"
#include "tm-threads.h"
#include "util-time.h"
#include "decode.h"
#include "util-debug.h"
#include "tm-modules.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>


#define PCAP_OVER_IP_BUFFER_SIZE 65536
#define PCAP_OVER_IP_RECONNECT_DELAY 2


typedef struct PcapOverIPThreadVars_ {
    int socket_fd;                
    char *server_ip;              
    int server_port;              
    bool swapped;                 // Indicates endian-swapped headers
    struct pcap_pkthdr current_hdr; 
    uint64_t packets_received;    // Counter for packets received
    uint64_t bytes_received;      // Counter for bytes received
    ChecksumValidationMode checksum_mode;
    ThreadVars *tv;
    TmSlot *slot;
} PcapOverIPThreadVars;


// Function prototypes
static TmEcode ReceivePcapOverIPThreadInit(ThreadVars *, const void *, void **);
static TmEcode ReceivePcapOverIPThreadDeinit(ThreadVars *, void *);
static TmEcode ReceivePcapOverIPLoop(ThreadVars *, void *, void *);
static void ReceivePcapOverIPThreadExitStats(ThreadVars *, void *);
static TmEcode DecodePcapOverIP(ThreadVars *, Packet *, void *);
static TmEcode DecodePcapOverIPThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodePcapOverIPThreadDeinit(ThreadVars *, void *);

// Module registration
void TmModuleReceivePcapOverIPRegister(void) {
    tmm_modules[TMM_RECEIVEPCAPOVERIP].name = "ReceivePcapOverIP";
    tmm_modules[TMM_RECEIVEPCAPOVERIP].ThreadInit = ReceivePcapOverIPThreadInit;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].PktAcqLoop = ReceivePcapOverIPLoop;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].ThreadDeinit = ReceivePcapOverIPThreadDeinit;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].ThreadExitPrintStats = ReceivePcapOverIPThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAPOVERIP].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodePcapOverIPRegister(void) {
    tmm_modules[TMM_DECODEPCAPOVERIP].name = "DecodePcapOverIP";
    tmm_modules[TMM_DECODEPCAPOVERIP].ThreadInit = DecodePcapOverIPThreadInit;
    tmm_modules[TMM_DECODEPCAPOVERIP].Func = DecodePcapOverIP;
    tmm_modules[TMM_DECODEPCAPOVERIP].ThreadDeinit = DecodePcapOverIPThreadDeinit;
    tmm_modules[TMM_DECODEPCAPOVERIP].flags = TM_FLAG_DECODE_TM;
}

static int ParsePcapOverIPInput(const char *input, char **server_ip, int *server_port) {
    if (!input || !server_ip || !server_port) {
        return -1;
    }

    char *input_copy = strdup(input);
    if (!input_copy) {
        return -1;
    }

    // Expect "tcp@ip:port" format
    if (strncmp(input_copy, "tcp@", 4) != 0) {
        free(input_copy);
        return -1;
    }

    char *colon = strchr(input_copy + 4, ':');
    if (!colon) {
        free(input_copy);
        return -1;
    }

    *colon = '\0';
    *server_ip = strdup(input_copy + 4);
    *server_port = atoi(colon + 1);

    free(input_copy);
    return (*server_ip && *server_port > 0) ? 0 : -1;
}

// Thread initialization
static TmEcode ReceivePcapOverIPThreadInit(ThreadVars *tv, const void *initdata, void **data) {
    char *server_ip = NULL;
    int server_port = 0;

    if (ParsePcapOverIPInput((const char *)initdata, &server_ip, &server_port) < 0) {
        SCLogError("Invalid input format. Expected tcp@ip:port");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapOverIPThreadVars *ptv = SCCalloc(1, sizeof(PcapOverIPThreadVars));
    if (!ptv) {
        SCLogError("Memory allocation failed.");
        free(server_ip);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->server_ip = server_ip;
    ptv->server_port = server_port;
    ptv->tv = tv;

    ptv->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ptv->socket_fd < 0) {
        SCLogError("Socket creation failed: %s", strerror(errno));
        free(ptv->server_ip);
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(ptv->server_port);
    if (inet_pton(AF_INET, ptv->server_ip, &server_addr.sin_addr) <= 0) {
        SCLogError("Invalid server IP address: %s", ptv->server_ip);
        close(ptv->socket_fd);
        free(ptv->server_ip);
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (connect(ptv->socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        SCLogError("Failed to connect to server %s:%d: %s", ptv->server_ip, ptv->server_port, strerror(errno));
        close(ptv->socket_fd);
        free(ptv->server_ip);
        SCFree(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("Connected to PCAP-over-IP server at %s:%d", ptv->server_ip, ptv->server_port);

    *data = ptv;
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceivePcapOverIPThreadDeinit(ThreadVars *tv, void *data) {
    PcapOverIPThreadVars *ptv = (PcapOverIPThreadVars *)data;
    if (ptv->socket_fd >= 0) {
        close(ptv->socket_fd);
    }
    free(ptv->server_ip);
    SCFree(ptv);
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceivePcapOverIPLoop(ThreadVars *tv, void *data, void *slot) {
    PcapOverIPThreadVars *ptv = (PcapOverIPThreadVars *)data;
    char buffer[PCAP_OVER_IP_BUFFER_SIZE];
    ssize_t bytes_received;

    while (!(suricata_ctl_flags & SURICATA_STOP)) {
        bytes_received = recv(ptv->socket_fd, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            SCLogError("Socket read error: %s", strerror(errno));
            break;
        }

        ptv->packets_received++;
        ptv->bytes_received += bytes_received;

        // Parse PCAP header and process packets
        struct pcap_pkthdr *hdr = (struct pcap_pkthdr *)buffer;
        const u_char *data = (const u_char *)(buffer + sizeof(struct pcap_pkthdr));

        Packet *p = PacketGetFromQueueOrAlloc();
        if (!p) {
            SCLogError("Failed to allocate packet.");
            break;
        }

        p->ts = SCTIME_FROM_TIMEVAL(&hdr->ts);
        p->datalink = DLT_EN10MB;
        if (PacketCopyData(p, data, hdr->caplen) < 0) {
            break;
        }

    if (unlikely(PacketCopyData(p, data, h->caplen))) {
        SCLogError("Failed to copy packet data.");
        TmqhOutputPacketpool(ptv->tv, p);
        break;
    }

        if (TmThreadsSlotProcessPkt(ptv->tv, slot, p) != TM_ECODE_OK) {
            SCLogError("Failed to process packet.");
            break;
        }
    }

    SCReturnInt(TM_ECODE_FAILED);
}

// Exit statistics
static void ReceivePcapOverIPThreadExitStats(ThreadVars *tv, void *data) {
    PcapOverIPThreadVars *ptv = (PcapOverIPThreadVars *)data;
    SCLogNotice("PCAP-over-IP: %" PRIu64 " packets, %" PRIu64 " bytes received", ptv->packets_received, ptv->bytes_received);
}

// Decode thread initialization
static TmEcode DecodePcapOverIPThreadInit(ThreadVars *tv, const void *initdata, void **data) {
    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (!dtv) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    DecodeRegisterPerfCounters(dtv, tv);
    *data = dtv;
    SCReturnInt(TM_ECODE_OK);
}

// Decode packets
static TmEcode DecodePcapOverIP(ThreadVars *tv, Packet *p, void *data) {
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;
    DecodeUpdatePacketCounters(tv, dtv, p);
    DecodeLinkLayer(tv, dtv, p->datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
    PacketDecodeFinalize(tv, dtv, p);
    SCReturnInt(TM_ECODE_OK);
}

// Decode thread deinitialization
static TmEcode DecodePcapOverIPThreadDeinit(ThreadVars *tv, void *data) {
    DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

