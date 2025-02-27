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
    cmd.verbose = -1;
    cmd.update_time = -1;
    cmd.no_stats = -1;
    cmd.stats_per_second = -1;
    cmd.stdout_update_time = -1;

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

    // Create overrides for config and set arguments from CLI.
    config_overrides_t cfg_overrides = {0};
    cfg_overrides.verbose = cmd.verbose;
    cfg_overrides.log_file = cmd.log_file;
    cfg_overrides.interface = cmd.interface;
    cfg_overrides.update_time = cmd.update_time;
    cfg_overrides.no_stats = cmd.no_stats;
    cfg_overrides.stats_per_second = cmd.stats_per_second;
    cfg_overrides.stdout_update_time = cmd.stdout_update_time;

    // Load config.
    if ((ret = LoadConfig(&cfg, cmd.cfgfile, &cfg_overrides)) != 0)
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

    // Check interface.
    if (cfg.interface == NULL)
    {
        LogMsg(&cfg, 0, 1, "[ERROR] No interface specified in config or CLI override.");

        return EXIT_FAILURE;
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
    int map_filters = FindMapFd(prog, "map_filters");

    // Check for valid maps.
    if (map_filters < 0)
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to find 'map_filters' BPF map.\n");

        return EXIT_FAILURE;
    }

    LogMsg(&cfg, 3, 0, "map_filters FD => %d.", map_filters);

    int map_stats = FindMapFd(prog, "map_stats");

    if (map_stats < 0)
    {
        LogMsg(&cfg, 0, 1, "[ERROR] Failed to find 'map_stats' BPF map.\n");

        return EXIT_FAILURE;
    }

#ifdef ENABLE_FILTER_LOGGING
    int map_filter_log = FindMapFd(prog, "map_filter_log");
    struct ring_buffer* rb = NULL;

    if (map_filter_log < 0)
    {
        LogMsg(&cfg, 1, 0, "[WARNING] Failed to find 'map_filter_log' BPF map. Filter logging will be disabled...");
    }
    else
    {
        LogMsg(&cfg, 3, 0, "map_filter_log FD => %d.", map_filter_log);

        rb = ring_buffer__new(map_filter_log, HandleRbEvent, &cfg, NULL);
    }
#endif

    LogMsg(&cfg, 3, 0, "map_stats FD => %d.", map_stats);

    LogMsg(&cfg, 2, 0, "Updating filters...");

    // Update BPF maps.
    UpdateFilters(map_filters, &cfg);

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
                // Update config.
                if ((ret = LoadConfig(&cfg, cmd.cfgfile, &cfg_overrides)) != 0)
                {
                    LogMsg(&cfg, 1, 0, "[WARNING] Failed to load config after update check (%d)...\n", ret);
                }

                // Update BPF maps.
                UpdateFilters(map_filters, &cfg);

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
            if (CalculateStats(map_stats, cpus, cfg.stats_per_second))
            {
                LogMsg(&cfg, 1, 0, "[WARNING] Failed to calculate packet stats. Stats map FD => %d...\n", map_stats);
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