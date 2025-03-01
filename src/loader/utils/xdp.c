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
 * Custom print function for LibBPF that doesn't print anything (silent mode).
 * 
 * @param level The current LibBPF log level.
 * @param format The message format.
 * @param args Format arguments for the message.
 * 
 * @return void
 */
static int LibBPFSilent(enum libbpf_print_level level, const char *format, va_list args)
{
    return 0;
}

/**
 * Sets custom LibBPF log mode.
 * 
 * @param silent If 1, disables LibBPF logging entirely.
 * 
 * @return void
 */
void SetLibBPFLogMode(int silent)
{
    if (silent)
    {
        libbpf_set_print(LibBPFSilent);
    }
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
 * Retrieves BPF object from XDP program.
 * 
 * @param prog A pointer to the XDP program.
 * 
 * @return The BPF object.
 */
struct bpf_object* GetBpfObj(struct xdp_program* prog)
{
    return xdp_program__bpf_obj(prog);
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mode_used The mode being used.
 * @param ifidx The index to the interface to attach to.
 * @param detach If above 0, attempts to detach XDP program.
 * @param force_skb If set, forces the XDP program to run in SKB mode.
 * @param force_offload If set, forces the XDP program to run in offload mode.
 * 
 * @return 0 on success and 1 on error.
 */
int AttachXdp(struct xdp_program *prog, char** mode, int ifidx, int detach, int force_skb, int force_offload)
{
    int err;

    u32 attach_mode = XDP_MODE_NATIVE;

    *mode = "DRV/native";

    if (force_offload)
    {
        *mode = "HW/offload";

        attach_mode = XDP_MODE_HW;
    }
    else if (force_skb)
    {
        *mode = "SKB/generic";
        
        attach_mode = XDP_MODE_SKB;
    }

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        if (detach)
        {
            err = xdp_program__detach(prog, ifidx, attach_mode, 0);
        }
        else
        {
            err = xdp_program__attach(prog, ifidx, attach_mode, 0);
        }

        if (err)
        {
            // Decrease mode.
            switch (attach_mode)
            {
                case XDP_MODE_HW:
                    attach_mode = XDP_MODE_NATIVE;
                    *mode = "DRV/native";

                    break;

                case XDP_MODE_NATIVE:
                    attach_mode = XDP_MODE_SKB;
                    *mode = "SKB/generic";

                    break;

                case XDP_MODE_SKB:
                    // Exit loop.
                    exit = 1;

                    *mode = NULL;
                    
                    break;
            }

            // Retry.
            continue;
        }
        
        // Success, so break current loop.
        break;
    }

    // If exit is set to 1 or smode is NULL, it indicates full failure.
    if (exit || *mode == NULL)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Deletes a filter.
 * 
 * @param map_filters The filters BPF map FD.
 * @param idx The filter index to delete.
 * 
 * @return 0 on success or the error value of bpf_map_delete_elem().
 */
int DeleteFilter(int map_filters, u32 idx)
{
    return bpf_map_delete_elem(map_filters, &idx);
}

/**
 * Deletes all filters.
 * 
 * @param map_filters The filters BPF map FD.
 * 
 * @return void
 */
void DeleteFilters(int map_filters)
{
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        DeleteFilter(map_filters, i);
    }
}

/**
 * Updates a filter rule.
 * 
 * @param map_filters The filters BPF map FD.
 * @param filter A pointer to the filter.
 * @param idx The filter index to insert or update.
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int UpdateFilter(int map_filters, filter_t* filter, int idx)
{
    int ret;

    filter_t filter_cpus[MAX_CPUS];
    memset(filter_cpus, 0, sizeof(filter_cpus));

    for (int j = 0; j < MAX_CPUS; j++)
    {
        filter_cpus[j] = *filter;
    }

    return bpf_map_update_elem(map_filters, &idx, &filter_cpus, BPF_ANY);
}

/**
 * Updates the filter's BPF map with current config settings.
 * 
 * @param map_filters The filter's BPF map FD.
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
 */
void UpdateFilters(int map_filters, config__t *cfg)
{
    int ret;
    int cur_idx = 0;

    // Add a filter to the filter maps.
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        // Delete previous rule from BPF map.
        // We do this in the case rules were edited and were put out of order since the key doesn't uniquely map to a specific rule.
        DeleteFilter(map_filters, i);

        filter_t* filter = &cfg->filters[i];

        // Only insert set and enabled filters.
        if (!filter->set || !filter->enabled)
        {
            continue;
        }

        // Attempt to update filter.
        if ((ret = UpdateFilter(map_filters, filter, cur_idx)) != 0)
        {
            fprintf(stderr, "[WARNING] Failed to update filter #%d due to BPF update error (%d)...\n", cur_idx, ret);

            continue;
        }

        cur_idx++;
    }
}

/**
 * Pins a BPF map to the file system.
 * 
 * @param obj A pointer to the BPF object.
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return 0 on success or value of bpf_map__pin() on error.
 */
int PinBpfMap(struct bpf_object* obj, const char* pin_dir, const char* map_name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);

    if (!map)
    {
        return -1;
    }

    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", XDP_MAP_PIN_DIR, map_name);

    return bpf_map__pin(map, full_path);
}

/**
 * Unpins a BPF map from the file system.
 * 
 * @param obj A pointer to the BPF object.
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return
 */
int UnpinBpfMap(struct bpf_object* obj, const char* pin_dir, const char* map_name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);

    if (!map)
    {
        return 1;
    }

    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", XDP_MAP_PIN_DIR, map_name);

    return bpf_map__unpin(map, full_path);
}

/**
 * Retrieves a map FD on the file system (pinned).
 * 
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return The map FD or -1 on error.
 */
int GetMapPinFd(const char* pin_dir, const char* map_name)
{
    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", pin_dir, map_name);

    return bpf_obj_get(full_path);
}

/**
 * Deletes IPv4 address from block map.
 * 
 * @param map_block The block map's FD.
 * @param ip The IP address to remove.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int DeleteBlock(int map_block, u32 ip)
{
    return bpf_map_delete_elem(map_block, &ip);
}

/**
 * Adds an IPv4 address to the block map.
 * 
 * @param map_block The block map's FD.
 * @param ip The IP address to add.
 * @param expires When the block expires (nanoseconds since system boot).
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int AddBlock(int map_block, u32 ip, u64 expires)
{
    return bpf_map_update_elem(map_block, &ip, &expires, BPF_ANY);
}

/**
 * Deletes IPv6 address from block map.
 * 
 * @param map_block6 The block map's FD.
 * @param ip The IP address to remove.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int DeleteBlock6(int map_block6, u128 ip)
{
    return bpf_map_delete_elem(map_block6, &ip);
}

/**
 * Adds an IPv6 address to the block map.
 * 
 * @param map_block6 The block map's FD.
 * @param ip The IP address to add.
 * @param expires When the block expires (nanoseconds since system boot).
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int AddBlock6(int map_block6, u128 ip, u64 expires)
{
    return bpf_map_update_elem(map_block6, &ip, &expires, BPF_ANY);
}

/**
 * Deletes an IPv4 range from the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param net The network IP.
 * @param cidr The network's CIDR.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem(). 
 */
int DeleteRangeDrop(int map_range_drop, u32 net, u8 cidr)
{
    u32 bit_mask = ( ~( (1 << (32 - cidr) ) - 1) );
    u32 start = net & bit_mask;

    LpmTrieKey key = {0};
    key.prefix_len = cidr;
    key.data = start;

    return bpf_map_delete_elem(map_range_drop, &key);
}

/**
 * Adds an IPv4 range to the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param net The network IP.
 * @param cidr The network's CIDR.
 * 
 * @return 0 on success or error value of bpf_map_update_elem(). 
 */
int AddRangeDrop(int map_range_drop, u32 net, u8 cidr)
{
    u32 bit_mask = ( ~( (1 << (32 - cidr) ) - 1) );
    u32 start = net & bit_mask;

    LpmTrieKey key = {0};
    key.prefix_len = cidr;
    key.data = start;

    u64 val = ( (u64)bit_mask << 32 ) | start;

    return bpf_map_update_elem(map_range_drop, &key, &val, BPF_ANY);
}

/**
 * Updates IP ranges from config file.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param cfg A pointer to the config file
 * 
 * @return void
 */
void UpdateRangeDrops(int map_range_drop, config__t* cfg)
{
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        const char* range = cfg->drop_ranges[i];

        if (!range)
        {
            continue;
        }

        // Parse IP range string and return network IP and CIDR.
        ip_range_t t = ParseIpCidr(range);

        AddRangeDrop(map_range_drop, t.ip, t.cidr);
    }
}