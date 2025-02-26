#include <loader/utils/logging.h>

/**
 * Prints a log message to stdout/stderr along with a file if specified.
 * 
 * @param req_lvl The required level for this message.
 * @param cur_lvl The current verbose level.
 * @param error If 1, sets pipe to stderr instead of stdout.
 * @param msg The log message.
 * @param args A VA list of arguments for the message.
 * 
 * @return void
 */
static void LogMsgRaw(int req_lvl, int cur_lvl, int error, const char* log_path, const char* msg, va_list args)
{
    if (cur_lvl < req_lvl)
    {
        return;
    }

    FILE* pipe = stdout;

    if (error)
    {
        pipe = stderr;
    }

    // We need to format the message.
    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(NULL, 0, msg, args_copy);
    va_end(args_copy);

    if (len < 0)
    {
        return;
    }

    char f_msg[len + 1];
    vsnprintf(f_msg, sizeof(f_msg), msg, args);

    char full_msg[len + 6 + 1];
    snprintf(full_msg, sizeof(full_msg), "[%d] %s", req_lvl, f_msg);

    fprintf(pipe, "%s\n", full_msg);

    if (log_path != NULL)
    {
        FILE* log_file = fopen(log_path, "a");

        if (!log_file)
        {
            return;
        }

        time_t now = time(NULL);
        struct tm* tm_val = localtime(&now);

        if (!tm_val)
        {
            fclose(log_file);

            return;
        }


        char log_file_msg[len + 22 + 1];

        snprintf(log_file_msg, sizeof(log_file_msg), "[%02d-%02d-%02d %02d:%02d:%02d]%s", tm_val->tm_year % 100, tm_val->tm_mon + 1, tm_val->tm_mday,
        tm_val->tm_hour, tm_val->tm_min, tm_val->tm_sec, full_msg);

        fprintf(log_file, "%s\n", log_file_msg);

        fclose(log_file);
    }
}

/**
 * Prints a log message using LogMsgRaw().
 * 
 * @param cfg A pointer to the config structure.
 * @param req_lvl The required level for this message.
 * @param error Whether this is an error.
 * @param msg The log message with format support.
 * 
 * @return void
 */
void LogMsg(config__t* cfg, int req_lvl, int error, const char* msg, ...)
{
    va_list args;
    va_start(args, msg);

    LogMsgRaw(req_lvl, cfg->verbose, error, (const char*)cfg->log_file, msg, args);

    va_end(args);
}