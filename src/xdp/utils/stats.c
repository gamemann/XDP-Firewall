#include <xdp/utils/stats.h>

static __always_inline int inc_pkt_stats(stats_t* stats, STATS_TYPE_T type)
{
    if (!stats)
    {
        return 1;
    }

    switch (type)
    {
        case STATS_TYPE_ALLOWED:
            stats->allowed++;

            break;

        case STATS_TYPE_PASSED:
            stats->passed++;

            break;

        case STATS_TYPE_DROPPED:
            stats->dropped++;

            break;
    }

    return 0;
}