#include <loader/utils/xdp.h>

/**
 * Finds a BPF map's FD.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mapname The name of the map to retrieve.
 * 
 * @return The map's FD.
 */
int FindMapFd(struct xdp_program *prog, const char *map_name)
{
    int fd = -1;

    struct bpf_object *obj = xdp_program__bpf_obj(prog);

    if (obj == NULL)
    {
        fprintf(stderr, "Error finding BPF object from XDP program.\n");

        goto out;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", map_name);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}

/**
 * Loads a BPF object file.
 * 
 * @param file_name The path to the BPF object file.
 * 
 * @return XDP program structure (pointer) or NULL.
 */
struct xdp_program *LoadBpfObj(const char *file_name)
{
    struct xdp_program *prog = xdp_program__open_file(file_name, "xdp_prog", NULL);

    if (prog == NULL)
    {
        // The main function handles this error.
        return NULL;
    }

    return prog;
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param ifidx The index to the interface to attach to.
 * @param detach If above 0, attempts to detach XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return 0 on success and 1 on error.
 */
int AttachXdp(struct xdp_program *prog, int ifidx, u8 detach, cmdline_t *cmd)
{
    int err;

    u32 mode = XDP_MODE_NATIVE;
    char *smode;

    smode = "DRV/native";

    if (cmd->offload)
    {
        smode = "HW/offload";

        mode = XDP_MODE_HW;
    }
    else if (cmd->skb)
    {
        smode = "SKB/generic";
        mode = XDP_MODE_SKB;
    }

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        if (detach)
        {
            err = xdp_program__detach(prog, ifidx, mode, 0);
        }
        else
        {
            err = xdp_program__attach(prog, ifidx, mode, 0);
        }

        if (err)
        {
            if (err)
            {
                fprintf(stderr, "Could not attach with mode %s (%s) (%d).\n", smode, strerror(-err), -err);
            }

            // Decrease mode.
            switch (mode)
            {
                case XDP_MODE_HW:
                    mode = XDP_MODE_NATIVE;
                    smode = "DRV/native";

                    break;

                case XDP_MODE_NATIVE:
                    mode = XDP_MODE_SKB;
                    smode = "SKB/generic";

                    break;

                case XDP_MODE_SKB:
                    // Exit loop.
                    exit = 1;
                    smode = NULL;
                    
                    break;
            }

            // Retry.
            continue;
        }
        
        // Success, so break current loop.
        break;
    }

    // If exit is set to 1 or smode is NULL, it indicates full failure.
    if (exit || smode == NULL)
    {
        return EXIT_FAILURE;
    }

    if (detach < 1)
    {
        fprintf(stdout, "Loaded XDP program on mode %s.\n", smode);
    }

    return EXIT_SUCCESS;
}

/**
 * Updates the filter's BPF map with current config settings.
 * 
 * @param filters_map The filter's BPF map FD.
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
 */
void UpdateFilters(int filters_map, config__t *cfg)
{
    int i;

    // Loop through all filters and delete the map. We do this in the case rules were edited and were put out of order since the key doesn't uniquely map to a specific rule.
    for (i = 0; i < MAX_FILTERS; i++)
    {
        u32 key = i;

        bpf_map_delete_elem(filters_map, &key);
    }

    // Add a filter to the filter maps.
    for (i = 0; i < MAX_FILTERS; i++)
    {
        // Check if we have a valid ID.
        if (cfg->filters[i].id < 1)
        {
            break;
        }

        // Create value array (max CPUs in size) since we're using a per CPU map.
        filter_t filter[MAX_CPUS];
        memset(filter, 0, sizeof(filter));

        for (int j = 0; j < MAX_CPUS; j++)
        {
            filter[j] = cfg->filters[i];
        }

        // Attempt to update BPF map.
        if (bpf_map_update_elem(filters_map, &i, &filter, BPF_ANY) == -1)
        {
            fprintf(stderr, "Error updating BPF item #%d\n", i);
        }
    }
}