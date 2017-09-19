/*
  ============================================================================
  Name        : pwstore.c
  Author      : Zoff <zoff@zoff.cc>
  Version     :
  Copyright   : (C) 2014 - 2017 Zoff <zoff@zoff.cc>
  Description : simple password mananger for unix scripts
  ============================================================================
  */

/**
 * pwstore
 * Copyright (C) 2014 - 2017 Zoff <zoff@zoff.cc>
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
  * to compile dynamic (normal) on linux:
  *   gcc -O3 pwstore.c -D LINUX -o pwstore
  *
  * to compile static on linux:
  *   gcc -static -O3 -D LINUX pwstore.c -o pwstore
  *
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

#define PWSTORE_DATA_DIR "/opt/pwstore/conf/"		// hardcoded location for now, TODO: make better somehow
#define VERSION "v0.99.6"							// version

void usage(char* s)
{
        printf("Version: %s %s\n", s, VERSION);
        printf("Usage  : %s list                - list all logins\n", s);
        printf("         %s read login [login2] - get password for login\n", s);
        printf("         %s  add login [login2] - store password for login\n", s);
}

void log_msg(const char* action, const char *msg, const char*msg2, const char* user)
{
#ifdef LINUX
        syslog(LOG_INFO, "user=%s action=%s %s%s", user, action, msg, msg2);
#else
        syslog((LOG_AUTH | LOG_INFO), "user=%s action=%s %s%s", user, action, msg, msg2);
        // ----------------------------------
        // only for debugging
        // printf("user=%s action=%s %s%s", user, action, msg, msg2);
        // only for debugging
        // ----------------------------------
#endif
}

void log_msg2(const char* action, const char *msg, const char*msg2, const char*msg3, const char* user)
{
#ifdef LINUX
                if (!msg3)
                {
                        syslog(LOG_INFO, "user=%s action=%s %s%s", user, action, msg, msg2);
                }
                else
                {
                        syslog(LOG_INFO, "user=%s action=%s %s%s_%s", user, action, msg, msg2, msg3);
                }
#else
                if (!msg3)
                {
                        syslog((LOG_AUTH | LOG_INFO), "user=%s action=%s %s%s", user, action, msg, msg2);
                }
                else
                {
                        syslog((LOG_AUTH | LOG_INFO), "user=%s action=%s %s%s_%s", user, action, msg, msg2, msg3);
                }
#endif

        // ----------------------------------
        // only for debugging
        // printf("user=%s action=%s %s%s %s", user, action, msg, msg2, msg3);
        // only for debugging
        // ----------------------------------
}

int main(int argc, char **argv)
{
        const char *pwstore_data_dir = PWSTORE_DATA_DIR;
        mode_t data_dir_mode = (S_IRUSR | S_IWUSR | S_IXUSR);
        mode_t data_file_mask = (S_IXUSR | S_IWGRP | S_IRGRP | S_IXGRP | S_IWOTH | S_IROTH | S_IXOTH);
        int create_user_data_dir = 0;
        char login_dir[8192]; // make buffer big enough

        if (argc == 1)
        {
                usage(argv[0]);
                return 0;
        }

        struct passwd *pw;
        uid_t uid;

        uid = getuid();
        pw = getpwuid(uid);

#ifdef LINUX
        openlog ("pwstore", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
#endif

        if (pw)
        {
                snprintf(login_dir, sizeof(login_dir), "%s%s", pwstore_data_dir, pw->pw_name);

                struct stat s;
                int err = stat(login_dir, &s);
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
                        DIR *d;
                        struct dirent *dir;

                        char data_dir_for_user[8192]; // make buffer big enough
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
                                                                char dir_entry[8192]; // make buffer big enough
                                                                snprintf(dir_entry, sizeof(dir_entry), "%s", dir->d_name);

                                                                // remove ".txt" from the filename
                                                                int len = strlen(dir_entry);
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
                        char login_file[8192]; // make buffer big enough
                                                if (argc == 4)
                                                {
                                                        snprintf(login_file, sizeof(login_file), "%s%s%s%s%s%s%s", pwstore_data_dir, pw->pw_name, "/", argv[2], "_", argv[3], ".txt");
                                                }
                                                else
                                                {
                                                        snprintf(login_file, sizeof(login_file), "%s%s%s%s%s", pwstore_data_dir, pw->pw_name, "/", argv[2], ".txt");
                                                }

                        FILE *file;
                        if ((file = fopen(login_file, "rb")) == NULL)
                        {
                                puts("-ERROR-007-");
                                log_msg2("READ", "-ERROR-007-: User trying to read password for ", argv[2], argv[3], pw->pw_name);
                                return 1;
                        }
                        else
                        {
                                // read password
                                char password[8192]; // make buffer big enough
                                char *ret2 = fgets(password, 8192, file);

                                if (ret2 == NULL)
                                {
                                        int ret = fclose(file);
                                        if (ret != 0)
                                        {
                                                puts("-ERROR-009-");
                                                log_msg2("READ", "-ERROR-009-: User trying to read password for ", argv[2], argv[3], pw->pw_name);
                                                return 1;
                                        }
                                }
                                else
                                {
                                        // print password to STDOUT with newline char at the end
                                        puts(password);
                                        log_msg2("READ", "User read password for ", argv[2], argv[3], pw->pw_name);
                                }

                                int ret = fclose(file);
                                if (ret != 0)
                                {
                                        // dont print this error, in case the password was print OK
                                        // puts("-WARNING-008-");
                                        log_msg2("READ", "-WARNING-008-: User trying to read password for ", argv[2], argv[3], pw->pw_name);
                                        return 1;
                                }
                        }
                }
                else if (strcmp("add", argv[1]) == 0)
                {
                        if (strlen(argv[2]) > 1)
                        {
                                char login_file[8192]; // make buffer big enough
								if (argc == 4)
								{
										snprintf(login_file, sizeof(login_file), "%s%s%s%s%s%s%s", pwstore_data_dir, pw->pw_name, "/", argv[2], "_", argv[3], ".txt");
								}
								else
								{
										snprintf(login_file, sizeof(login_file), "%s%s%s%s%s", pwstore_data_dir, pw->pw_name, "/", argv[2], ".txt");
								}

                                char *password1;
                                char *password2;
                                char pass1[8192]; // make buffer big enough

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
                                        // passwords dont match
                                        puts("-ERROR-004-");
                                        return 1;
                                }

                                mode_t oldMask = umask((mode_t) 0);
                                mode_t newMask = data_file_mask;
                                umask(newMask);

                                if (create_user_data_dir == 1)
                                {
                                        int ret = mkdir(login_dir, data_dir_mode);
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

                                FILE *file;
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

                                        int ret = fclose(file);
                                        if (ret != 0)
                                        {
                                                puts("-ERROR-005-");
                                                return 1;
                                        }
                                }

                                umask(oldMask);
                        }
                        else
                        {
                                puts("-ERROR-003-");
                                return 1;
                        }
                }
        }
        else
        {
                usage(argv[0]);
                return 0;
        }

        return 0;
}

