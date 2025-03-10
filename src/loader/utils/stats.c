#include <loader/utils/stats.h>

struct timespec last_update_time = {0};

u64 last_allowed = 0;
u64 last_dropped = 0;
u64 last_passed = 0;

/**
 * Calculates and displays packet counters/stats.
 * 
 * @param map_stats The stats map BPF FD.
 * @param cpus The amount of CPUs the host has.
 * @param per_second Calculate packet counters per second (PPS).
 * 
 * @return 0 on success or 1 on failure.
 */
int calc_stats(int map_stats, int cpus, int per_second)
{
    u32 key = 0;

    stats_t stats[MAX_CPUS];
    memset(stats, 0, sizeof(stats));

    u64 allowed = 0;
    u64 dropped = 0;
    u64 passed = 0;
    
    if (bpf_map_lookup_elem(map_stats, &key, stats) != 0)
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

    u64 allowed_val = allowed, dropped_val = dropped, passed_val = passed;

    if (per_second)
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        
        double elapsed_time = (now.tv_sec - last_update_time.tv_sec) +
                              (now.tv_nsec - last_update_time.tv_nsec) / 1e9; 

        if (elapsed_time > 0)
        {
            allowed_val = (allowed - last_allowed) / elapsed_time;
            dropped_val = (dropped - last_dropped) / elapsed_time;
            passed_val = (passed - last_passed) / elapsed_time;
        }

        last_allowed = allowed;
        last_dropped = dropped;
        last_passed = passed;
        last_update_time = now;
    }

    char allowed_str[12];
    char dropped_str[12];
    char passed_str[12];

    if (per_second)
    {
        snprintf(allowed_str, sizeof(allowed_str), "%llu PPS", allowed_val);
        snprintf(dropped_str, sizeof(dropped_str), "%llu PPS", dropped_val);
        snprintf(passed_str, sizeof(passed_str), "%llu PPS", passed_val);
    }
    else
    {
        snprintf(allowed_str, sizeof(allowed_str), "%llu", allowed_val);
        snprintf(dropped_str, sizeof(dropped_str), "%llu", dropped_val);
        snprintf(passed_str, sizeof(passed_str), "%llu", passed_val);
    }
    
    printf("\r\033[1;32mAllowed:\033[0m %s  |  ", allowed_str);
    printf("\033[1;31mDropped:\033[0m %s  |  ", dropped_str);
    printf("\033[1;34mPassed:\033[0m %s", passed_str);

    fflush(stdout);    

    return EXIT_SUCCESS;
}