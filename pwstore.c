/*
  ============================================================================
  Name        : pwstore.c
  Author      : Zoff <zoff@zoff.cc>
  Version     :
  Copyright   : (C) 2014 - 2025 Zoff <zoff@zoff.cc>
  Description : simple password mananger for unix scripts
  ============================================================================
  */

/**
 * pwstore
 * Copyright (C) 2014 - 2025 Zoff <zoff@zoff.cc>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

/*
   to compile dynamic (normal) on linux:
     gcc -O3 -g -Wall -Wextra -pedantic \
       -Wvla \
       -Werror=div-by-zero \
       -fno-omit-frame-pointer \
       -D_FORTIFY_SOURCE=2 \
       -fstack-protector-all --param=ssp-buffer-size=1 \
       -D LINUX pwstore.c -o pwstore

   to compile static on linux:
     gcc -static -O3 -g -Wall -Wextra -pedantic \
       -Wvla \
       -Werror=div-by-zero \
       -fno-omit-frame-pointer \
       -D_FORTIFY_SOURCE=2 \
       -fstack-protector-all --param=ssp-buffer-size=1 \
       -D LINUX pwstore.c -o pwstore

 */

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>

// dirent.h

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeclaration-after-statement"

#define PWSTORE_DATA_DIR "/opt/pwstore/conf/"       // hardcoded location for now, TODO: make better somehow
#define VERSION "v0.99.13"                          // version

#define TEXT_BUFFER_LEN (8192)
#define REPLACE_CHAR (char)(95) // "_"

static void usage(char *s)
{
    printf("Version: %s %s\n", s, VERSION);
    printf("Usage  : %s   list                - list all logins\n", s);
    printf("         %s   read login [login2] - get password for login\n", s);
    printf("         %s    add login [login2] - store password for login\n", s);
    printf("         %s revoke login [login2] - remove password for login\n", s);
    printf("         %s    del login [login2] - remove password for login\n", s);
    printf("\n");
    printf("Errors :\n");
    printf("\n");
    printf("-ERROR-001- Unix user does not exist or is an empty value\n");
    printf("-ERROR-002- Error creating directory for user password files\n");
    printf("-ERROR-003- \"login\" parameter must be at least 2 characters long on adding password\n");
    printf("-ERROR-004- Entered passwords do not match\n");
    printf("-ERROR-005- Error closing password file\n");
    printf("-ERROR-006- Error opening or creating password file\n");
    printf("-ERROR-007- Error opening password file\n");
    printf("-WARNG-008- This will not be printed, just logged\n");
    printf("-ERROR-009- Error reading from password file\n");
    printf("-ERROR-010- \"login\" parameter must be at least 2 characters long on deleting password\n");
    printf("-ERROR-011- Error deleting password file to revoke password\n");
    printf("-ERROR-012- Unix user contains bad characters\n");
    printf("-ERROR-013- Unix user is empty or has zero length\n");
    printf("\n");
}

static void log_msg(const char *action, const char *msg, const char *msg2, const char *user)
{
#ifdef LINUX
    syslog(LOG_INFO, "version=%s user=%s action=%s %s%s", VERSION, user, action, msg, msg2);
#else
    syslog((LOG_AUTH | LOG_INFO), "version=%s user=%s action=%s %s%s", VERSION, user, action, msg, msg2);
    // ----------------------------------
    // only for debugging
    // printf("version=%s user=%s action=%s %s%s", VERSION, user, action, msg, msg2);
    // only for debugging
    // ----------------------------------
#endif
}

static void log_msg2(const char *action, const char *msg, const char *msg2, const char *msg3, const char *user)
{
#ifdef LINUX
    if (!msg3)
    {
        syslog(LOG_INFO, "version=%s user=%s action=%s %s%s", VERSION, user, action, msg, msg2);
    }
    else
    {
        syslog(LOG_INFO, "version=%s user=%s action=%s %s%s_%s", VERSION, user, action, msg, msg2, msg3);
    }
#else
    if (!msg3)
    {
        syslog((LOG_AUTH | LOG_INFO), "version=%s user=%s action=%s %s%s", VERSION, user, action, msg, msg2);
    }
    else
    {
        syslog((LOG_AUTH | LOG_INFO), "version=%s user=%s action=%s %s%s_%s", VERSION, user, action, msg, msg2, msg3);
    }
#endif
    // ----------------------------------
    // only for debugging
    // printf("version=%s user=%s action=%s %s%s %s", VERSION, user, action, msg, msg2, msg3);
    // only for debugging
    // ----------------------------------
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantParameter"
static void replace_bad_char_from_string(char *str, const char replace_with)
{
    // replace those: '\ / : * ? " < > | .'
    char bad_chars[] = "\\./:*?<>|\"";
    int i = 0;
    int j = 0;

    if ((str) && (strlen(str) > 0))
    {
        for (i = 0; (int)i < (int)strlen(str) ; i++)
        {
            for (j = 0; (int)j < (int)strlen(bad_chars); j++)
            {
                if (str[i] == bad_chars[j])
                {
                    str[i] = replace_with;
                }
            }
        }
    }
}
#pragma clang diagnostic pop

static int check_bad_char_in_string(const char *str)
{
    // check for those: '\ / : * ? " < > | .'
    char bad_chars[] = "\\./:*?<>|\"";
    int i = 0;
    int j = 0;

    if ((str) && (strlen(str) > 0))
    {
        for (i = 0; (int)i < (int)strlen(str) ; i++)
        {
            for (j = 0; (int)j < (int)strlen(bad_chars); j++)
            {
                if (str[i] == bad_chars[j])
                {
                    return -1;
                }
            }
        }
    }
    else
    {
        return -2;
    }

    return 0;
}

static void func_list(const char *pwstore_data_dir, const struct passwd *pw)
{
    DIR *d;
    const struct dirent *dir;
    char data_dir_for_user[TEXT_BUFFER_LEN + 1]; // make buffer big enough
    memset(data_dir_for_user, 0, TEXT_BUFFER_LEN + 1);
    snprintf(data_dir_for_user, sizeof(data_dir_for_user), "%s%s%s", pwstore_data_dir, pw->pw_name, "/");
    d = opendir(data_dir_for_user);

    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (strcmp(".", dir->d_name) != 0)
            {
                if (strcmp("..", dir->d_name) != 0)
                {
                    if (strlen(dir->d_name) > 4)
                    {
                        char dir_entry[TEXT_BUFFER_LEN + 1]; // make buffer big enough
                        memset(dir_entry, 0, TEXT_BUFFER_LEN + 1);
                        snprintf(dir_entry, sizeof(dir_entry), "%s", dir->d_name);
                        // remove ".txt" from the filename
                        const int len = (int)(strlen(dir_entry));
                        dir_entry[len - 4] = '\0';
                        // list all logins
                        printf("%s\n", dir_entry);
                    }
                }
            }
        }
        closedir(d);
    }
}

static int func_read(const char *pwstore_data_dir, const struct passwd *pw, int argc, char *const *argv)
{
    replace_bad_char_from_string(argv[2], REPLACE_CHAR);

    char login_file[TEXT_BUFFER_LEN + 1]; // make buffer big enough
    memset(login_file, 0, TEXT_BUFFER_LEN + 1);

    if (argc == 4)
    {
        replace_bad_char_from_string(argv[3], REPLACE_CHAR);
        snprintf(login_file, sizeof(login_file), "%s%s%s%s%s%s%s",
                 pwstore_data_dir, pw->pw_name, "/", argv[2], "_", argv[3], ".txt");
    }
    else
    {
        snprintf(login_file, sizeof(login_file), "%s%s%s%s%s",
                 pwstore_data_dir, pw->pw_name, "/", argv[2], ".txt");
    }

    FILE *file = NULL;

    if ((file = fopen(login_file, "rb")) == NULL)
    {
        puts("-ERROR-007-");
        log_msg2("READ", "-ERROR-007-: User trying to read password for ",
                 argv[2], argv[3], pw->pw_name);
        return 1;
    }
    else
    {
        // read password
        char password[TEXT_BUFFER_LEN + 1]; // make buffer big enough
        memset(password, 0, TEXT_BUFFER_LEN + 1);
        const char *ret2 = fgets(password, TEXT_BUFFER_LEN, file);

        if (ret2 == NULL)
        {
            const int ret = fclose(file);
            if (ret){}
            puts("-ERROR-009-");
            log_msg2("READ", "-ERROR-009-: User trying to read password for ", argv[2], argv[3], pw->pw_name);
            return 1;
        }
        else
        {
            // print password to STDOUT with newline char at the end
            puts(password);
            log_msg2("READ", "User read password for ", argv[2], argv[3], pw->pw_name);
        }

        const int ret = fclose(file);

        if (ret != 0)
        {
            // do not print this error, in case the password did print to stdout OK
            // puts("-WARNG-008-");
            log_msg2("READ", "-WARNG-008-: User trying to read password for ", argv[2], argv[3], pw->pw_name);
            return 1;
        }
    }

    return 0;
}

static int func_del(const char *pwstore_data_dir, const struct passwd *pw, int argc, char *const *argv)
{
    if (strlen(argv[2]) > 1)
    {
        replace_bad_char_from_string(argv[2], REPLACE_CHAR);

        char login_file[TEXT_BUFFER_LEN + 1]; // make buffer big enough
        memset(login_file, 0, TEXT_BUFFER_LEN + 1);

        if (argc == 4)
        {
            replace_bad_char_from_string(argv[3], REPLACE_CHAR);
            snprintf(login_file, sizeof(login_file), "%s%s%s%s%s%s%s",
                     pwstore_data_dir, pw->pw_name, "/", argv[2], "_", argv[3], ".txt");
        }
        else
        {
            snprintf(login_file, sizeof(login_file), "%s%s%s%s%s",
                     pwstore_data_dir, pw->pw_name, "/", argv[2], ".txt");
        }

        const int result = unlink(login_file);

        if (result == 0)
        {
            log_msg2("REVOKE", "User revoked password for ", argv[2], argv[3], pw->pw_name);
            return 0;
        }
        else
        {
            puts("-ERROR-011-");
            log_msg2("REVOKE", "-ERROR-011-: User revoking password for ", argv[2], argv[3], pw->pw_name);
            return 1;
        }
    }
    else
    {
        puts("-ERROR-010-");
        return 1;
    }
}

static int func_add(const char *pwstore_data_dir, const struct passwd *pw, int argc, char *const *argv,
             const mode_t data_dir_mode, const mode_t data_file_mask, int create_user_data_dir,
             const char *login_dir)
{
    if (strlen(argv[2]) > 1)
    {
        replace_bad_char_from_string(argv[2], REPLACE_CHAR);

        char login_file[TEXT_BUFFER_LEN + 1]; // make buffer big enough
        memset(login_file, 0, TEXT_BUFFER_LEN + 1);

        if (argc == 4)
        {
            replace_bad_char_from_string(argv[3], REPLACE_CHAR);
            snprintf(login_file, sizeof(login_file), "%s%s%s%s%s%s%s",
                     pwstore_data_dir, pw->pw_name, "/", argv[2], "_", argv[3], ".txt");
        }
        else
        {
            snprintf(login_file, sizeof(login_file), "%s%s%s%s%s",
                     pwstore_data_dir, pw->pw_name, "/", argv[2], ".txt");
        }

        const char *password1;
        const char *password2;
        char pass1[TEXT_BUFFER_LEN + 1]; // make buffer big enough
        memset(pass1, 0, TEXT_BUFFER_LEN + 1);
#ifdef LINUX
        password1 = getpass("password: ");
#else
        password1 = getpassphrase("password: ");
#endif
        snprintf(pass1, sizeof(pass1), "%s", password1);
#ifdef LINUX
        password2 = getpass("   again: ");
#else
        password2 = getpassphrase("   again: ");
#endif

        if (strcmp(pass1, password2) != 0)
        {
            // passwords do not match
            puts("-ERROR-004-");
            return 1;
        }

        const mode_t oldMask = umask((mode_t) 0);
        const mode_t newMask = data_file_mask;
        umask(newMask);

        if (create_user_data_dir == 1)
        {
            const int ret = mkdir(login_dir, data_dir_mode);
            if (ret != 0)
            {
                puts("-ERROR-002-");
                umask(oldMask);
                return 1;
            }
            else
            {
                log_msg("MKDIR", "User created directory ", login_dir, pw->pw_name);
            }
        }

        FILE *file = NULL;

        if ((file = fopen(login_file, "wb")) == NULL)
        {
            puts("-ERROR-006-");
            umask(oldMask);
            return 1;
        }
        else
        {
            fprintf(file, "%s", password2);
            log_msg2("ADD", "User added password for ", argv[2], argv[3], pw->pw_name);
            umask(oldMask);
            const int ret = fclose(file);
            if (ret != 0)
            {
                puts("-ERROR-005-");
                return 1;
            }
        }

        umask(oldMask);
        return 0;
    }
    else
    {
        puts("-ERROR-003-");
        return 1;
    }
}

int main(int argc, char **argv)
{
    const char *pwstore_data_dir = PWSTORE_DATA_DIR;
    const mode_t data_dir_mode = (S_IRUSR | S_IWUSR | S_IXUSR);
    const mode_t data_file_mask = (S_IXUSR | S_IWGRP | S_IRGRP | S_IXGRP | S_IWOTH | S_IROTH | S_IXOTH);
    int create_user_data_dir = 0;
    char login_dir[TEXT_BUFFER_LEN + 1]; // make buffer big enough
    memset(login_dir, 0, TEXT_BUFFER_LEN + 1);

    if (argc == 1)
    {
        usage(argv[0]);
        return 0;
    }

    const uid_t uid = getuid();
    const struct passwd *pw = getpwuid(uid);

#ifdef LINUX
    openlog("pwstore", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
#endif

    if (pw)
    {
        /*
            adduser: To avoid problems, the username should consist only of
                        letters, digits, underscores, periods, at signs and dashes, and
                        not start with a dash (as defined by IEEE Std 1003.1-2001). For
                        compatibility with Samba machine accounts, $ is also supported
                        at the end of the username.  (Use the `--allow-all-names' option
                        to bypass this restriction.)
        */

        /*
        * pw->pw_name may contain special characters
        * we need to check for them and return an error
        */
        int is_bad_username = check_bad_char_in_string(pw->pw_name);
        if (is_bad_username != 0)
        {
            if (is_bad_username == -1)
            {
                puts("-ERROR-012-");
                log_msg2("CHKUSR", "-ERROR-012-: Username contains bad characters ", argv[2], argv[3], pw->pw_name);
                return 1;
            }
            else
            {
                puts("-ERROR-013-");
                log_msg2("CHKUSR", "-ERROR-013-: Username is empty or has zero length ", argv[2], argv[3], "*empty*");
                return 1;
            }
        }

        snprintf(login_dir, sizeof(login_dir), "%s%s", pwstore_data_dir, pw->pw_name);
        struct stat s;
        const int err = stat(login_dir, &s);
        if (err == -1)
        {
            if (ENOENT == errno)
            {
                /* does not exist, create the dir */
                create_user_data_dir = 1;
            }
        }
    }
    else
    {
        puts("-ERROR-001-");
        return 1;
    }

    if (argc == 2)
    {
        if (strcmp("list", argv[1]) == 0)
        {
            func_list(pwstore_data_dir, pw);
            return 0;
        }
        else
        {
            usage(argv[0]);
            return 0;
        }
    }
    else if ((argc == 3) || (argc == 4))
    {
        if (strcmp("read", argv[1]) == 0)
        {
            return func_read(pwstore_data_dir, pw, argc, argv);
        }
        else if (strcmp("add", argv[1]) == 0)
        {
            return func_add(pwstore_data_dir, pw, argc, argv, data_dir_mode, data_file_mask,
                            create_user_data_dir,
                            login_dir);
        }
        else if ((strcmp("del", argv[1]) == 0) || (strcmp("revoke", argv[1]) == 0))
        {
            return func_del(pwstore_data_dir, pw, argc, argv);
        }
    }
    else
    {
        usage(argv[0]);
        return 0;
    }

    return 0;
}

#pragma clang diagnostic pop
