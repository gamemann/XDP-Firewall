#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <signal.h>

#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>

#include <net/if.h>

#include <loader/utils/cmdline.h>
#include <loader/utils/config.h>
#include <loader/utils/xdp.h>
#include <loader/utils/logging.h>
#include <loader/utils/stats.h>
#include <loader/utils/helpers.h>

int cont = 1;
int doing_stats = 0;

int main(int argc, char *argv[])
{
    int ret;

    // Parse the command line.
    cmdline_t cmd = {0};
    cmd.cfgfile = CONFIG_DEFAULT_PATH;

    ParseCommandLine(&cmd, argc, argv);

    // Check for help.
    if (cmd.help)
    {
        PrintHelpMenu();

        return EXIT_SUCCESS;
    }

    // Initialize config.
    config__t cfg = {0};

    SetCfgDefaults(&cfg);

    // Load config.
    if ((ret = LoadConfig(&cfg, cmd.cfgfile)) != 0)
    {
        fprintf(stderr, "[ERROR] Failed to load config from file system (%s)(%d).\n", cmd.cfgfile, ret);

        return EXIT_FAILURE;
    }

    // Check for list option.
    if (cmd.list)
    {
        PrintConfig(&cfg);

        return EXIT_SUCCESS;
    }

    // Print tool info.
    if (cfg.verbose > 0)
    {
        PrintToolInfo();
    }

    LogMsg(&cfg, 2, 0, "Raising RLimit...");

    // Raise RLimit.
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to raise rlimit. Please make sure this program is ran as root!\n");

        return EXIT_FAILURE;
    }

    LogMsg(&cfg, 2, 0, "Retrieving interface index for '%s'...", cfg.interface);

    // Get interface index.
    int ifidx = if_nametoindex(cfg.interface);

    if (ifidx < 0)
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to retrieve index of network interface '%s'.\n", cfg.interface);

        return EXIT_FAILURE;
    }

    LogMsg(&cfg, 2, 0, "Loading XDP/BPF program at '%s'...", XDP_OBJ_PATH);

    // Determine custom LibBPF log level.
    int silent = 1;

    if (cfg.verbose > 4)
    {
        silent = 0;
    }

    SetLibBPFLogMode(silent);

    // Load BPF object.
    struct xdp_program *prog = LoadBpfObj(XDP_OBJ_PATH);

    if (prog == NULL)
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to load eBPF object file. Object path => %s.\n", XDP_OBJ_PATH);

        return EXIT_FAILURE;
    }

    LogMsg(&cfg, 2, 0, "Attaching XDP program to interface '%s'...", cfg.interface);
    
    // Attach XDP program.
    char *mode_used = NULL;

    if ((ret = AttachXdp(prog, &mode_used, ifidx, 0, &cmd)) != 0)
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to attach XDP program to interface '%s' using available modes (%d).\n", cfg.interface, ret);

        return EXIT_FAILURE;
    }

    if (mode_used != NULL)
    {
        LogMsg(&cfg, 1, 0, "Attached XDP program using mode '%s'...", mode_used);
    }

    LogMsg(&cfg, 2, 0, "Retrieving BPF map FDs...");

    // Retrieve BPF maps.
    int filters_map = FindMapFd(prog, "filters_map");

    // Check for valid maps.
    if (filters_map < 0)
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to find 'filters_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    LogMsg(&cfg, 3, 0, "filters_map FD => %d.", filters_map);

    int stats_map = FindMapFd(prog, "stats_map");

    if (stats_map < 0)
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to find 'stats_map' BPF map.\n");

        return EXIT_FAILURE;
    }

#ifdef ENABLE_FILTER_LOGGING
    int filter_log_map = FindMapFd(prog, "filter_log_map");
    struct ring_buffer* rb = NULL;

    if (filter_log_map < 0)
    {
        LogMsg(&cfg, 1, 0, "[WARNING] Failed to find 'filter_log_map' BPF map. Filter logging will be disabled...");
    }
    else
    {
        LogMsg(&cfg, 3, 0, "filter_log_map FD => %d.", filter_log_map);

        rb = ring_buffer__new(filter_log_map, HandleRbEvent, &cfg, NULL);
    }
#endif

    LogMsg(&cfg, 3, 0, "stats_map FD => %d.", stats_map);

    LogMsg(&cfg, 2, 0, "Updating filters...");

    // Update BPF maps.
    UpdateFilters(filters_map, &cfg);

    // Signal.
    signal(SIGINT, SignalHndl);
    signal(SIGTERM, SignalHndl);

    // Receive CPU count for stats map parsing.
    int cpus = get_nprocs_conf();

    LogMsg(&cfg, 4, 0, "Retrieved %d CPUs on host.", cpus);

    unsigned int end_time = (cmd.time > 0) ? time(NULL) + cmd.time : 0;

    // Create last updated variables.
    time_t last_update_check = time(NULL);
    time_t last_config_check = time(NULL);

    unsigned int sleep_time = cfg.stdout_update_time * 1000;

    struct stat conf_stat;

    // Check if we're doing stats.
    if (!cfg.no_stats)
    {
        doing_stats = 1;
    }

    while (cont)
    {
        // Get current time.
        time_t cur_time = time(NULL);

        // Check if we should end the program.
        if (end_time > 0 && cur_time >= end_time)
        {
            break;
        }

        // Check for auto-update.
        if (cfg.update_time > 0 && (cur_time - last_update_check) > cfg.update_time)
        {
            // Check if config file have been modified
            if (stat(cmd.cfgfile, &conf_stat) == 0 && conf_stat.st_mtime > last_config_check) {
                // Memleak fix for strdup() in LoadConfig()
                // Before updating it again, we need to free the old return value
                free(cfg.interface);

                // Update config.
                if ((ret = LoadConfig(&cfg, cmd.cfgfile)) != 0)
                {
                    LogMsg(&cfg, 1, 0, "[WARNING] Failed to load config after update check (%d)...\n", ret);
                }

                // Update BPF maps.
                UpdateFilters(filters_map, &cfg);

                // Update timer
                last_config_check = time(NULL);

                // Make sure we set doing stats if needed.
                if (!cfg.no_stats && !doing_stats)
                {
                    doing_stats = 1;
                }
            }

            // Update last updated variable.
            last_update_check = time(NULL);
        }

        // Calculate and display stats if enabled.
        if (!cfg.no_stats)
        {
            if (CalculateStats(stats_map, cpus, cfg.stats_per_second))
            {
                LogMsg(&cfg, 1, 0, "[WARNING] Failed to calculate packet stats. Stats map FD => %d...\n", stats_map);
            }
        }

#ifdef ENABLE_FILTER_LOGGING
        PollFiltersRb(rb);
#endif

        usleep(sleep_time);
    }

    fprintf(stdout, "\n");

#ifdef ENABLE_FILTER_LOGGING
    if (rb)
    {
        ring_buffer__free(rb);
    }
#endif

    // Detach XDP program.
    if (AttachXdp(prog, &mode_used, ifidx, 1, &cmd))
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to detach XDP program from interface '%s'.\n", cfg.interface);

        return EXIT_FAILURE;
    }

    LogMsg(&cfg, 1, 0, "Cleaned up and exiting...\n");

    // Exit program successfully.
    return EXIT_SUCCESS;
}