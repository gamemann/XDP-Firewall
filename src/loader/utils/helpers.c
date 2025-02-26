#include <loader/utils/helpers.h>

/**
 * Prints help menu.
 * 
 * @return void
 */
void PrintHelpMenu()
{
    fprintf(stdout, "Usage:\n" \
        "--config -c => Config file location (default is /etc/xdpfw/xdpfw.conf).\n" \
        "--offload -o => Tries to load the XDP program in hardware/offload mode.\n" \
        "--skb -s => Force the XDP program to load with SKB mode instead of DRV.\n" \
        "--time -t => How long to run the program for in seconds before exiting. 0 or not set = infinite.\n" \
        "--list -l => Print config details including filters (this will exit program after done).\n" \
        "--help -h => Print help menu.\n");
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

    char *token = strtok((char *) ip, "/");

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