#include <loader/utils/helpers.h>

/**
 * Prints help menu.
 * 
 * @return void
 */
void PrintHelpMenu()
{
    printf("Usage: xdpfw [OPTIONS]\n\n");

    printf("  -c, --config         Config file location (default: /etc/xdpfw/xdpfw.conf).\n");
    printf("  -o, --offload        Load the XDP program in hardware/offload mode.\n");
    printf("  -s, --skb            Force the XDP program to load with SKB mode instead of DRV.\n");
    printf("  -t, --time           Duration to run the program (seconds). 0 or unset = infinite.\n");
    printf("  -l, --list           Print config details including filters (exits after execution).\n");
    printf("  -h, --help           Show this help message.\n\n");
    printf("  -v, --verbose        Override config's verbose value.\n");
    printf("      --log-file       Override config's log file value.\n");
    printf("  -i, --interface      Override config's interface value.\n");
    printf("  -u, --update-time    Override config's update time value.\n");
    printf("  -n, --no-stats       Override config's no stats value.\n");
    printf("      --stats-ps       Override config's stats per second value.\n");
    printf("      --stdout-ut      Override config's stdout update time value.\n");
}

/**
 * Handles signals from user.
 * 
 * @param code Signal code.
 * 
 * @return void
 */
void SignalHndl(int code)
{
    cont = 0;
}

/**
 * Parses an IP string with CIDR support. Stores IP in network byte order in ip.ip and CIDR in ip.cidr.
 * 
 * @param ip The IP string.
 * 
 * @return Returns an IP structure with IP and CIDR. 
 */
ip_range_t ParseIpCidr(const char *ip)
{
    ip_range_t ret = {0};
    ret.cidr = 32;

    char ip_copy[INET_ADDRSTRLEN + 3];
    strncpy(ip_copy, ip, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';

    char *token = strtok((char *) ip_copy, "/");

    if (token)
    {
        ret.ip = inet_addr(token);

        token = strtok(NULL, "/");

        if (token)
        {
            ret.cidr = (u8) strtoul(token, NULL, 10);
        }
    }

    return ret;
}

/**
 * Retrieves protocol name by ID.
 * 
 * @param id The protocol ID
 * 
 * @return The protocol string. 
 */
const char* GetProtocolStrById(int id)
{
    switch (id)
    {
        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_UDP:
            return "UDP";
        
        case IPPROTO_ICMP:
            return "ICMP";
    }

    return "N/A";
}

/**
 * Prints tool name and author.
 * 
 * @return void
 */
void PrintToolInfo()
{
    printf(
        " __  ______  ____    _____ _                        _ _ \n"
        " \\ \\/ /  _ \\|  _ \\  |  ___(_)_ __ _____      ____ _| | |\n"
        "  \\  /| | | | |_) | | |_  | | '__/ _ \\ \\ /\\ / / _` | | |\n"
        "  /  \\| |_| |  __/  |  _| | | | |  __/\\ V  V / (_| | | |\n"
        " /_/\\_\\____/|_|     |_|   |_|_|  \\___| \\_/\\_/ \\__,_|_|_|\n"
        "\n\n"
    );
}

/**
 * Retrieves nanoseconds since system boot.
 * 
 * @return The current nanoseconds since the system last booted.
 */
u64 GetBootNanoTime()
{
    struct sysinfo sys;
    sysinfo(&sys);

    return sys.uptime * 1e9;
}