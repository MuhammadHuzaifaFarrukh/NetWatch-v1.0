#define HAVE_REMOTE
#include <pcap.h>
#include <mutex>
#include <thread>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <atomic>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

// ─── Ethernet / IP / TCP / UDP / ICMP Headers ───────────────────────────────

#pragma pack(push, 1)
struct EthernetHeader
{
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

struct IPv4Header
{
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct TCPHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

struct UDPHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct ICMPHeader
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};
#pragma pack(pop)

// ─── Packet Record ────────────────────────────────────────────────────────────

struct PacketRecord
{
    std::string time;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    int packet_size;
    int src_port;
    int dst_port;
    std::string service;
};

// ─── Globals ─────────────────────────────────────────────────────────────────

std::vector<PacketRecord> g_packets;
std::mutex g_mutex;
std::atomic<bool> g_capturing(false);
pcap_t *g_handle = nullptr;
int g_total_packets = 0;
std::map<std::string, int> g_proto_count;
long long g_total_size = 0;

// ─── Port → Service Map ───────────────────────────────────────────────────────

std::string portToService(int port)
{
    static std::map<int, std::string> svcMap = {
        {20, "FTP-Data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"}, {68, "DHCP"}, {69, "TFTP"}, {80, "HTTP"}, {110, "POP3"}, {119, "NNTP"}, {123, "NTP"}, {143, "IMAP"}, {161, "SNMP"}, {194, "IRC"}, {443, "HTTPS"}, {445, "SMB"}, {465, "SMTPS"}, {500, "IKE"}, {514, "Syslog"}, {587, "SMTP"}, {993, "IMAPS"}, {995, "POP3S"}, {1080, "SOCKS"}, {1194, "OpenVPN"}, {1433, "MSSQL"}, {1521, "Oracle"}, {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"}, {5900, "VNC"}, {6379, "Redis"}, {6881, "BitTorrent"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"}, {27017, "MongoDB"}};
    auto it = svcMap.find(port);
    return (it != svcMap.end()) ? it->second : "Unknown";
}

// ─── IP to string ─────────────────────────────────────────────────────────────

std::string ipToString(uint32_t ip)
{
    in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

// ─── Get Timestamp ────────────────────────────────────────────────────────────

std::string getTimestamp()
{
    time_t now = time(nullptr);
    struct tm *t = localtime(&now);
    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", t);
    return std::string(buf);
}

// ─── Packet Handler ───────────────────────────────────────────────────────────

void packetHandler(u_char *, const struct pcap_pkthdr *header, const u_char *pkt)
{
    if (!g_capturing)
        return;

    PacketRecord rec;
    rec.time = getTimestamp();
    rec.packet_size = header->len;
    rec.src_port = 0;
    rec.dst_port = 0;
    rec.service = "N/A";

    const EthernetHeader *eth = (EthernetHeader *)pkt;
    if (ntohs(eth->type) != 0x0800)
        return; // IPv4 only

    const IPv4Header *ip = (IPv4Header *)(pkt + sizeof(EthernetHeader));
    int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;

    rec.src_ip = ipToString(ip->src_ip);
    rec.dst_ip = ipToString(ip->dst_ip);

    const u_char *transport = (u_char *)ip + ip_hdr_len;

    if (ip->protocol == 6)
    {
        rec.protocol = "TCP";
        const TCPHeader *tcp = (TCPHeader *)transport;
        rec.src_port = ntohs(tcp->src_port);
        rec.dst_port = ntohs(tcp->dst_port);
        rec.service = portToService(rec.dst_port);
        if (rec.service == "Unknown")
            rec.service = portToService(rec.src_port);
    }
    else if (ip->protocol == 17)
    {
        rec.protocol = "UDP";
        const UDPHeader *udp = (UDPHeader *)transport;
        rec.src_port = ntohs(udp->src_port);
        rec.dst_port = ntohs(udp->dst_port);
        rec.service = portToService(rec.dst_port);
        if (rec.service == "Unknown")
            rec.service = portToService(rec.src_port);
    }
    else if (ip->protocol == 1)
    {
        rec.protocol = "ICMP";
        rec.service = "ICMP";
    }
    else
    {
        rec.protocol = "OTHER";
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    g_packets.push_back(rec);
    g_total_packets++;
    g_proto_count[rec.protocol]++;
    g_total_size += rec.packet_size;
}

// ─── Capture Thread ───────────────────────────────────────────────────────────

void captureThread(std::string dev)
{
    // ---- 1. Sanitize device string (fix double-escaped backslashes) ----
    {
        std::string fixed;
        fixed.reserve(dev.size());
        for (size_t i = 0; i < dev.size(); ++i)
        {
            if (dev[i] == '\\' && i + 1 < dev.size() && dev[i + 1] == '\\')
            {
                fixed.push_back('\\');
                ++i; // skip the duplicate
            }
            else
            {
                fixed.push_back(dev[i]);
            }
        }
        dev = fixed;
    }

    std::cerr << "Opening device: [" << dev << "]\n";

    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // ---- 2. Create handle ----
    g_handle = pcap_create(dev.c_str(), errbuf);
    if (!g_handle)
    {
        std::cerr << "pcap_create failed: " << errbuf << "\n";
        return;
    }

    // ---- 3. Configure (promiscuous first attempt) ----
    pcap_set_snaplen(g_handle, 65536);
    pcap_set_promisc(g_handle, 1);
    pcap_set_timeout(g_handle, 1000);
    pcap_set_immediate_mode(g_handle, 1); // real-time packet delivery

    int rc = pcap_activate(g_handle);

    // ---- 4. Retry without promiscuous mode if it failed (common on Wi-Fi) ----
    if (rc < 0)
    {
        std::cerr << "pcap_activate failed (" << rc << "): "
                  << pcap_geterr(g_handle)
                  << " — retrying without promiscuous mode...\n";

        pcap_close(g_handle);
        g_handle = pcap_create(dev.c_str(), errbuf);
        if (!g_handle)
        {
            std::cerr << "pcap_create (retry) failed: " << errbuf << "\n";
            return;
        }
        pcap_set_snaplen(g_handle, 65536);
        pcap_set_promisc(g_handle, 0);
        pcap_set_timeout(g_handle, 1000);
        pcap_set_immediate_mode(g_handle, 1);

        rc = pcap_activate(g_handle);
        if (rc < 0)
        {
            std::cerr << "pcap_activate retry failed (" << rc << "): "
                      << pcap_geterr(g_handle) << "\n";
            pcap_close(g_handle);
            g_handle = nullptr;
            return;
        }
    }

    if (rc > 0)
    {
        std::cerr << "pcap_activate warning (" << rc << "): "
                  << pcap_geterr(g_handle) << "\n";
    }

    // ---- 5. Apply BPF filter (IP traffic only) ----
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, "ip", 1, PCAP_NETMASK_UNKNOWN) == 0)
    {
        if (pcap_setfilter(g_handle, &fp) != 0)
        {
            std::cerr << "pcap_setfilter failed: " << pcap_geterr(g_handle) << "\n";
        }
        pcap_freecode(&fp);
    }
    else
    {
        std::cerr << "pcap_compile failed: " << pcap_geterr(g_handle) << "\n";
    }

    std::cerr << "Capture started on: " << dev << "\n";

    // ---- 6. Capture loop ----
    while (g_capturing)
    {
        struct pcap_pkthdr *header = nullptr;
        const u_char *data = nullptr;
        int res = pcap_next_ex(g_handle, &header, &data);

        if (res == 1)
        {
            // Got a packet — call your existing handler.
            // Replace `packetHandler` with whatever your project uses.
            packetHandler(nullptr, header, data);
        }
        else if (res == 0)
        {
            // Timeout elapsed, no packet — keep looping
            continue;
        }
        else if (res == -1)
        {
            std::cerr << "pcap_next_ex error: " << pcap_geterr(g_handle) << "\n";
            break;
        }
        else if (res == -2)
        {
            // pcap_breakloop called
            break;
        }
    }

    // ---- 7. Cleanup ----
    if (g_handle)
    {
        pcap_close(g_handle);
        g_handle = nullptr;
    }
    std::cerr << "Capture stopped on: " << dev << "\n";
}

// ─── JSON Helpers ─────────────────────────────────────────────────────────────

std::string escapeJson(const std::string &s)
{
    std::string out;
    for (char c : s)
    {
        if (c == '"')
            out += "\\\"";
        else if (c == '\\')
            out += "\\\\";
        else
            out += c;
    }
    return out;
}

std::string buildPacketsJson()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < g_packets.size(); i++)
    {
        const auto &p = g_packets[i];
        oss << "{\"time\":\"" << escapeJson(p.time) << "\","
            << "\"src_ip\":\"" << escapeJson(p.src_ip) << "\","
            << "\"dst_ip\":\"" << escapeJson(p.dst_ip) << "\","
            << "\"protocol\":\"" << escapeJson(p.protocol) << "\","
            << "\"packet_size\":" << p.packet_size << ","
            << "\"src_port\":" << p.src_port << ","
            << "\"dst_port\":" << p.dst_port << ","
            << "\"service\":\"" << escapeJson(p.service) << "\"}";
        if (i + 1 < g_packets.size())
            oss << ",";
    }
    oss << "]";
    return oss.str();
}

std::string buildStatsJson()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    std::ostringstream oss;
    double avg_size = g_total_packets > 0 ? (double)g_total_size / g_total_packets : 0;
    oss << "{\"total_packets\":" << g_total_packets
        << ",\"avg_size\":" << (int)avg_size
        << ",\"tcp\":" << g_proto_count["TCP"]
        << ",\"udp\":" << g_proto_count["UDP"]
        << ",\"icmp\":" << g_proto_count["ICMP"]
        << ",\"other\":" << g_proto_count["OTHER"]
        << ",\"capturing\":" << (g_capturing ? "true" : "false")
        << "}";
    return oss.str();
}

std::string buildDevicesJson()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs;
    std::ostringstream oss;
    oss << "[";
    if (pcap_findalldevs(&devs, errbuf) == 0)
    {
        bool first = true;
        for (pcap_if_t *d = devs; d != nullptr; d = d->next)
        {
            if (!first)
                oss << ",";
            std::string name = d->name ? d->name : "";
            std::string desc = d->description ? d->description : name;
            oss << "{\"name\":\"" << escapeJson(name) << "\","
                << "\"desc\":\"" << escapeJson(desc) << "\"}";
            first = false;
        }
        pcap_freealldevs(devs);
    }
    oss << "]";
    return oss.str();
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

std::string readFully(SOCKET sock)
{
    std::string req;
    char buf[4096];
    int n;
    // Read headers first
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0)
    {
        buf[n] = '\0';
        req += buf;
        if (req.find("\r\n\r\n") != std::string::npos)
            break;
    }
    // Read body if Content-Length exists
    size_t cl_pos = req.find("Content-Length: ");
    if (cl_pos != std::string::npos)
    {
        int cl = std::stoi(req.substr(cl_pos + 16));
        size_t body_pos = req.find("\r\n\r\n");
        int already = (int)req.size() - (int)(body_pos + 4);
        while (already < cl)
        {
            n = recv(sock, buf, sizeof(buf) - 1, 0);
            if (n <= 0)
                break;
            buf[n] = '\0';
            req += buf;
            already += n;
        }
    }
    return req;
}

void sendResponse(SOCKET sock, int code, const std::string &ctype, const std::string &body)
{
    std::string status = (code == 200) ? "200 OK" : (code == 400 ? "400 Bad Request" : "404 Not Found");
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << "\r\n"
        << "Content-Type: " << ctype << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        << "Access-Control-Allow-Headers: Content-Type, Accept\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    std::string resp = oss.str();
    send(sock, resp.c_str(), (int)resp.size(), 0);
}

void handleClient(SOCKET sock)
{
    std::string req = readFully(sock);
    if (req.empty())
    {
        closesocket(sock);
        return;
    }

    // Parse method + path
    std::istringstream iss(req);
    std::string method, path, ver;
    iss >> method >> path >> ver;

    // Handle CORS preflight
    if (method == "OPTIONS")
    {
        std::string resp = "HTTP/1.1 200 OK\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                           "Access-Control-Allow-Headers: Content-Type, Accept\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n";
        send(sock, resp.c_str(), (int)resp.size(), 0);
        closesocket(sock);
        return;
    }

    // Route: GET /api/packets
    if (path == "/api/packets")
    {
        sendResponse(sock, 200, "application/json", buildPacketsJson());
    }
    // Route: GET /api/stats
    else if (path == "/api/stats")
    {
        sendResponse(sock, 200, "application/json", buildStatsJson());
    }
    // Route: GET /api/devices
    else if (path == "/api/devices")
    {
        sendResponse(sock, 200, "application/json", buildDevicesJson());
    }
    // Route: POST /api/start?dev=...
    else if (path == "/api/start" && !g_capturing)
    {
        // Read device name from JSON body
        std::string dev = "";
        size_t cl_pos = req.find("Content-Length: ");
        if (cl_pos != std::string::npos)
        {
            int cl = std::stoi(req.substr(cl_pos + 16));
            size_t body_pos = req.find("\r\n\r\n");
            if (body_pos != std::string::npos)
            {
                std::string body = req.substr(body_pos + 4, cl);
                // Extract dev value from JSON {"dev":"..."}
                size_t dpos = body.find("\"dev\":\"");
                if (dpos != std::string::npos)
                {
                    dpos += 7;
                    size_t dend = body.find("\"", dpos);
                    dev = body.substr(dpos, dend - dpos);
                }
            }
        }
        if (dev.empty())
        {
            sendResponse(sock, 400, "application/json", "{\"error\":\"No device specified\"}");
        }
        else
        {
            g_capturing = true;
            std::thread(captureThread, dev).detach();
            sendResponse(sock, 200, "application/json", "{\"status\":\"started\"}");
        }
    }
    // Route: POST /api/stop
    else if (path == "/api/stop")
    {
        g_capturing = false;
        sendResponse(sock, 200, "application/json", "{\"status\":\"stopped\"}");
    }
    // Route: POST /api/clear
    else if (path == "/api/clear")
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_packets.clear();
        g_total_packets = 0;
        g_proto_count.clear();
        g_total_size = 0;
        sendResponse(sock, 200, "application/json", "{\"status\":\"cleared\"}");
    }
    else
    {
        sendResponse(sock, 404, "application/json", "{\"error\":\"Not found\"}");
    }
    closesocket(sock);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    if (bind(server, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        std::cerr << "Bind failed. Is port 8080 in use?" << std::endl;
        return 1;
    }
    listen(server, 10);
    std::cout << "========================================\n";
    std::cout << "  Network Traffic Monitor - C++ Backend \n";
    std::cout << "  Listening on http://localhost:8080     \n";
    std::cout << "  Open index.html in your browser       \n";
    std::cout << "========================================\n";

    while (true)
    {
        SOCKET client = accept(server, nullptr, nullptr);
        if (client == INVALID_SOCKET)
            continue;
        std::thread(handleClient, client).detach();
    }

    closesocket(server);
    WSACleanup();
    return 0;
}
