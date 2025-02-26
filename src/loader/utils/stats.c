#include <loader/utils/stats.h>

/**
 * Calculates and displays packet counters/stats.
 * 
 * @param stats_map The stats map BPF FD.
 * @param cpus The amount of CPUs the host has.
 * 
 * @return 0 on success or 1 on failure.
 */
int CalculateStats(int stats_map, int cpus)
{
    u32 key = 0;

    stats_t stats[MAX_CPUS];
    memset(stats, 0, sizeof(stats));

    u64 allowed = 0;
    u64 dropped = 0;
    u64 passed = 0;
    
    if (bpf_map_lookup_elem(stats_map, &key, stats) != 0)
    {
        return EXIT_FAILURE;
    }

    for (int i = 0; i < cpus; i++)
    {
        // Although this should NEVER happen, I'm seeing very strange behavior in the following GitHub issue.
        // https://github.com/gamemann/XDP-Firewall/issues/10
        // Therefore, before accessing stats[i], make sure the pointer to the specific CPU ID is not NULL.
        if (&stats[i] == NULL)
        {
            fprintf(stderr, "[WARNING] Stats array at CPU ID #%d is NULL! Skipping...\n", i);

            continue;
        }

        allowed += stats[i].allowed;
        dropped += stats[i].dropped;
        passed += stats[i].passed;
    }
    
    printf("\r\033[1;32mAllowed:\033[0m %llu  |  ", allowed);
    printf("\033[1;31mDropped:\033[0m %llu  |  ", dropped);
    printf("\033[1;34mPassed:\033[0m %llu", passed);

    fflush(stdout);    

    return EXIT_SUCCESS;
}