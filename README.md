# DiscSniff
## Windows Network Sniffer That Sends Output To Discord Webhook
### Why did I make this? Well imagine this, no Kali Laptop :( No Shark Jack :( No Raspberry Pi :( Life is педераст.
This script can use any Windows PC in your hands to sniff network traffic when you don't have your special tools with you, or if you have remote access to one you can sniff traffic from affar and still get
that juicy PCAP file to your Discord Webhook.
> [!WARNING]
> USE AT YOUR OWN RISK I AM NOT RESPONSIBLE FOR ABUSE OF POWER

Like most things in life you need some preperation

> [!NOTE]
> On Discord, go to Edit Server and click on Integrations, from here create a Webhook and copy that URL so you can get that loot
> 
> Install [Npcap](https://npcap.com/#download) for the PC to sniff traffic
>
> Install Curl for the Windows cmd (most likely already installed especially if Git is installed) to send data
>
> Have a compiler for the C file, I used Microsofts compiler in VS Code
>
> Put your Webhook URL ***in Line 126*** where it says to do so

Now you are all set, you should have an exe file with your Webhook inserted & Npcap and Curl installed, now go get those PCAPS
