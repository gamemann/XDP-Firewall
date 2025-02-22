#include <loader/utils/helpers.h>

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
            ret.cidr = (unsigned int) strtoul(token, NULL, 10);
        }
    }

    return ret;
}