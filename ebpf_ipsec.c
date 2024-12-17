
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define TC_ACT_OK 0   //succesful return code;
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define IPPROTO_UDP 17  // udp prococol #
#define UDP_PORT 12345  // define port
#define P 23             // p = 23
#define G 5              // g = 5

// shared key
int shared_key = 0;
int a = 0;   //alice's shared key
int b = 0;    // bob's shared key

// packet counters
int ingress_count = 0;
int egress_count = 0;

// modular exponentiation func (g^a mod p)
int mod_exp(int g, int exp, int p) {
    int result = 1;
    g = g % p;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * g) % p;
        }
        exp = exp >> 1;
        g = (g * g) % p;
    }
    return result;
}

// XOR function
void xor_(char *data, int length, int key) {
    for (int i = 0; i < length; i++) {
        data[i] ^= key & 0xFF; 
    }
}

SEC("tc")
int tc_ingress_outgress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end; //declared pointer; points to end of packet data
    void *data = (void *)(__u64)ctx->data;//declares pointer to beginnig
    struct ethhdr *l2;//points to ethernet headter
    struct iphdr *l3;//points to ip header
    
    if (ctx->protocol != bpf_htons(ETH_P_IP))// checks if incoming is an ip packet
        return TC_ACT_OK;

    l2 = data;//set ethernet header to beginning of data
    if ((void *)(l2 + 1) > data_end)//check if there is enough room
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);//set l3 pointer to ip header
    if ((void *)(l3 + 1) > data_end)//cheching to see if room
        return TC_ACT_OK;

//////////////////////////////////////////////////////////////////////////////////////////////

    struct udphdr *udp;   //pointer to udp header
    int udp_length;  //udp length
    
    if (l3->protocol != IPPROTO_UDP)  //check if protocol is udp (17)
        return TC_ACT_OK;

    // process udp header
    udp = (struct udphdr *)(l3 + 1);// check to see if there is room
    udp_length = bpf_ntohs(udp->len);  // get  packet length
    
    if ((void *)(udp + 1) > data_end || udp_length < sizeof(struct udphdr))//see if it fits in buff
        return TC_ACT_OK;

    if (bpf_ntohs(udp->dest) != UDP_PORT && bpf_ntohs(udp->source) != UDP_PORT)  //verify port is 123345
        return TC_ACT_OK;

    // outgoing messages (egress)
    if (bpf_ntohs(udp->dest) == UDP_PORT) {
        egress_count++; // increment

        // generate alice's public key
        if (shared_key == 0) {
            a = bpf_get_prandom_u32() % (P - 1) + 1;  // random private key
            int a_public = mod_exp(G, a, P);
            
            // put public ket in payload
            char *payload = (char *)(udp + 1);
            unsigned int payload_length = udp_length - sizeof(struct udphdr);
            
            // replace blank space with public key A
            if (payload_length >= sizeof(a_public)) {
                *(unsigned int *)payload = bpf_htons(a_public);  // Network byte order
                bpf_printk("alice public key: %d", a_public);
            }
        }

        // encrypy with xor
        if (shared_key != 0) {
            char *payload = (char *)(udp + 1);
            unsigned int payload_length = udp_length - sizeof(struct udphdr);
            xor_(payload, payload_length, shared_key);
            bpf_printk("Encrypted egress message with shared key: %d", shared_key);
        }
    }

    // incoming messages (ingress)
    if (bpf_ntohs(udp->source) == UDP_PORT) {
        ingress_count++; // update ingress message counter

        // after bub gets alice's public key
        if (shared_key == 0) {
            b = bpf_get_prandom_u32() % (P - 1) + 1;  // ramdom private key
            unsigned int b_public = mod_exp(G, b, P);

            // get alice's publik key from payload
            char *payload = (char *)(udp + 1);
            unsigned int payload_length = udp_length - sizeof(struct udphdr);
            
            if (payload_length >= sizeof(a_public)) {
                unsigned int a_public = bpf_ntohl(*(unsigned int *)payload); // Network byte order
                bpf_printk("bob received alice's public key: %d", a_public);
                
                // derive shared key
                shared_key = mod_exp(a_public, b, P);
                bpf_printk("bob shared key: %d", shared_key);

                // send bob's public key
                if (payload_length >= sizeof(b_public)) {
                    *(unsigned int *)payload = bpf_htons(b_public;  // Network byte order
                    bpf_printk("bob public key: %d", b_public);
                }
            }
        }

        // decrypt with xor
        if (shared_key != 0) {
            char *payload = (char *)(udp + 1);
            unsigned int payload_length = udp_length - sizeof(struct udphdr);
            xor_(payload, payload_length, shared_key);
            bpf_printk("Decrypted ingress message with shared key: %d", shared_key);
        }
    }

    // log message counts
    bpf_printk("ingress count: %d, egress count: %d", ingress_count, egress_count);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

//cat /sys/kernel/debug/tracing/trace_pipe
