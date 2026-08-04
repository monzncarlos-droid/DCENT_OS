/*
 * dcentos-deploy-path - exact filesystem operations for deploy recovery.
 *
 * Copyright (C) 2026 D-Central Technologies
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#error "dcentos-deploy-path requires O_CLOEXEC"
#endif
#ifndef O_NOFOLLOW
#error "dcentos-deploy-path requires O_NOFOLLOW"
#endif

#define EX_USAGE 64
#define EX_UNAVAILABLE 69
#define PROBE_NAMESPACE ".dcent-deploy-path-probe"
#define PROBE_LOCK "lock"

struct path_operand {
    char *storage;
    const char *parent;
    const char *name;
    int parent_fd;
};

static void close_operand(struct path_operand *operand)
{
    if (operand->parent_fd >= 0) {
        (void)close(operand->parent_fd);
    }
    free(operand->storage);
    operand->storage = NULL;
    operand->parent_fd = -1;
}

static int open_operand(const char *path, struct path_operand *operand)
{
    char *slash;

    memset(operand, 0, sizeof(*operand));
    operand->parent_fd = -1;
    if (path == NULL || path[0] != '/' || path[1] == '\0' ||
        path[strlen(path) - 1] == '/') {
        fprintf(stderr,
                "dcentos-deploy-path: operands must be absolute, non-root paths\n");
        return -1;
    }
    operand->storage = strdup(path);
    if (operand->storage == NULL) {
        perror("dcentos-deploy-path: strdup");
        return -1;
    }
    slash = strrchr(operand->storage, '/');
    operand->name = slash + 1;
    if (strcmp(operand->name, ".") == 0 || strcmp(operand->name, "..") == 0) {
        fprintf(stderr,
                "dcentos-deploy-path: dot path components are not operands\n");
        close_operand(operand);
        return -1;
    }
    if (slash == operand->storage) {
        operand->parent = "/";
    } else {
        *slash = '\0';
        operand->parent = operand->storage;
    }
    operand->parent_fd = open(operand->parent,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (operand->parent_fd < 0) {
        perror("dcentos-deploy-path: open parent");
        close_operand(operand);
        return -1;
    }
    return 0;
}

static bool same_object(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           (left->st_mode & S_IFMT) == (right->st_mode & S_IFMT);
}

static int inspect_nondirectory(int parent_fd, const char *name,
                                struct stat *result)
{
    if (fstatat(parent_fd, name, result, AT_SYMLINK_NOFOLLOW) != 0) {
        perror("dcentos-deploy-path: inspect source");
        return -1;
    }
    if (S_ISDIR(result->st_mode)) {
        fprintf(stderr,
                "dcentos-deploy-path: refusing a directory source\n");
        return -1;
    }
    return 0;
}

static int require_absent(int parent_fd, const char *name)
{
    struct stat observed;

    if (fstatat(parent_fd, name, &observed, AT_SYMLINK_NOFOLLOW) == 0) {
        fprintf(stderr,
                "dcentos-deploy-path: destination already exists\n");
        return -1;
    }
    if (errno != ENOENT) {
        perror("dcentos-deploy-path: inspect destination");
        return -1;
    }
    return 0;
}

static int require_private_directory(int directory_fd)
{
    struct stat metadata;

    if (fstat(directory_fd, &metadata) != 0) {
        perror("dcentos-deploy-path: inspect private directory");
        return -1;
    }
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 07777) != 0700) {
        fprintf(stderr,
                "dcentos-deploy-path: transaction directory is not private to the effective user\n");
        return -1;
    }
    return 0;
}

static int verify_present(int parent_fd, const char *name,
                          const struct stat *expected)
{
    struct stat observed;

    if (fstatat(parent_fd, name, &observed, AT_SYMLINK_NOFOLLOW) != 0 ||
        !same_object(expected, &observed)) {
        fprintf(stderr,
                "dcentos-deploy-path: path identity verification failed\n");
        return -1;
    }
    return 0;
}

static int verify_absent(int parent_fd, const char *name)
{
    struct stat observed;

    if (fstatat(parent_fd, name, &observed, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        fprintf(stderr,
                "dcentos-deploy-path: source name remained after retirement\n");
        return -1;
    }
    return 0;
}

/* The destination is a root-owned mode-0700 transaction directory. Therefore
 * plain renameat has a no-clobber precondition against every unprivileged
 * actor while remaining compatible with Linux 4.4 filesystems lacking
 * renameat2(RENAME_NOREPLACE), including the canonical UBIFS baseline. */
static int retire_at(int source_parent, const char *source_name,
                     int destination_parent, const char *destination_name)
{
    struct stat source_before;

    if (require_private_directory(destination_parent) != 0 ||
        inspect_nondirectory(source_parent, source_name, &source_before) != 0 ||
        require_absent(destination_parent, destination_name) != 0) {
        return -1;
    }
    if (renameat(source_parent, source_name,
                 destination_parent, destination_name) != 0) {
        perror("dcentos-deploy-path: atomic retirement renameat");
        return -1;
    }
    if (verify_absent(source_parent, source_name) != 0 ||
        verify_present(destination_parent, destination_name, &source_before) != 0) {
        return -1;
    }
    return 0;
}

/* linkat is an atomic no-clobber publication on the Linux 4.4 baseline. The
 * private source alias is intentionally retained, so recovery never performs
 * a check-then-unlink against a restored foreign object. */
static int restore_link_at(int source_parent, const char *source_name,
                           int destination_parent, const char *destination_name)
{
    struct stat source_before;

    if (require_private_directory(source_parent) != 0 ||
        inspect_nondirectory(source_parent, source_name, &source_before) != 0 ||
        require_absent(destination_parent, destination_name) != 0) {
        return -1;
    }
    if (linkat(source_parent, source_name,
               destination_parent, destination_name, 0) != 0) {
        perror("dcentos-deploy-path: no-clobber restore linkat");
        return -1;
    }
    if (verify_present(source_parent, source_name, &source_before) != 0 ||
        verify_present(destination_parent, destination_name, &source_before) != 0) {
        return -1;
    }
    return 0;
}

static int run_path_operation(const char *operation, const char *source_path,
                              const char *destination_path)
{
    struct path_operand source;
    struct path_operand destination;
    int result = -1;

    if (strcmp(source_path, destination_path) == 0) {
        fprintf(stderr,
                "dcentos-deploy-path: source and destination must differ\n");
        return -1;
    }
    if (open_operand(source_path, &source) != 0) {
        return -1;
    }
    if (open_operand(destination_path, &destination) != 0) {
        close_operand(&source);
        return -1;
    }
    if (strcmp(operation, "retire") == 0) {
        result = retire_at(source.parent_fd, source.name,
                           destination.parent_fd, destination.name);
    } else if (strcmp(operation, "restore-link") == 0) {
        result = restore_link_at(source.parent_fd, source.name,
                                 destination.parent_fd, destination.name);
    }
    close_operand(&destination);
    close_operand(&source);
    return result;
}

static int create_probe_file(int directory_fd, const char *name)
{
    static const char payload[] = "dcentos deploy path probe\n";
    int file_fd;
    ssize_t written;

    file_fd = openat(directory_fd, name,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     0600);
    if (file_fd < 0) {
        return -1;
    }
    written = write(file_fd, payload, sizeof(payload) - 1U);
    if (written != (ssize_t)(sizeof(payload) - 1U) || fsync(file_fd) != 0) {
        (void)close(file_fd);
        return -1;
    }
    return close(file_fd);
}

struct probe_entry_spec {
    const char *name;
    mode_t type;
};

static int directory_contains_only(int directory_fd,
                                   const struct probe_entry_spec *allowed,
                                   size_t allowed_count)
{
    struct dirent *entry;
    DIR *stream;
    int scan_fd;
    size_t index;

    scan_fd = dup(directory_fd);
    if (scan_fd < 0) {
        return -1;
    }
    stream = fdopendir(scan_fd);
    if (stream == NULL) {
        (void)close(scan_fd);
        return -1;
    }
    errno = 0;
    while ((entry = readdir(stream)) != NULL) {
        bool recognized = false;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        for (index = 0; index < allowed_count; ++index) {
            if (strcmp(entry->d_name, allowed[index].name) == 0) {
                recognized = true;
                break;
            }
        }
        if (!recognized) {
            fprintf(stderr,
                    "dcentos-deploy-path: probe namespace contains an unknown entry\n");
            (void)closedir(stream);
            return -1;
        }
        errno = 0;
    }
    if (errno != 0) {
        (void)closedir(stream);
        return -1;
    }
    return closedir(stream);
}

static int remove_validated_probe_entry(int directory_fd,
                                        const struct probe_entry_spec *entry)
{
    struct stat metadata;

    if (fstatat(directory_fd, entry->name, &metadata,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if ((metadata.st_mode & S_IFMT) != entry->type ||
        metadata.st_uid != geteuid() || metadata.st_nlink < 1 ||
        metadata.st_nlink > 2 ||
        (entry->type == S_IFREG && (metadata.st_mode & 07777) != 0600)) {
        fprintf(stderr,
                "dcentos-deploy-path: stale probe entry metadata is not admissible\n");
        return -1;
    }
    return unlinkat(directory_fd, entry->name, 0);
}

static int reconcile_probe_operand_directory(
    int probe_fd, const char *name, const struct probe_entry_spec *allowed,
    size_t allowed_count)
{
    struct stat metadata;
    int directory_fd;
    int result = 0;
    size_t index;

    if (fstatat(probe_fd, name, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISDIR(metadata.st_mode)) {
        fprintf(stderr,
                "dcentos-deploy-path: probe operand path is not a directory\n");
        return -1;
    }
    directory_fd = openat(probe_fd, name,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0 || require_private_directory(directory_fd) != 0 ||
        directory_contains_only(directory_fd, allowed, allowed_count) != 0) {
        if (directory_fd >= 0) {
            (void)close(directory_fd);
        }
        return -1;
    }
    for (index = 0; index < allowed_count; ++index) {
        if (remove_validated_probe_entry(directory_fd, &allowed[index]) != 0) {
            result = -1;
        }
    }
    if (close(directory_fd) != 0) {
        result = -1;
    }
    if (result == 0 && unlinkat(probe_fd, name, AT_REMOVEDIR) != 0) {
        result = -1;
    }
    return result;
}

static int reconcile_probe_namespace(int probe_fd)
{
    static const struct probe_entry_spec root_entries[] = {
        {PROBE_LOCK, S_IFREG}, {"live", S_IFDIR}, {"private", S_IFDIR}
    };
    static const struct probe_entry_spec live_entries[] = {
        {"regular-source", S_IFREG},
        {"regular-restored", S_IFREG},
        {"collision", S_IFREG},
        {"symlink-restored", S_IFLNK}
    };
    static const struct probe_entry_spec private_entries[] = {
        {"regular-retired", S_IFREG}, {"symlink-source", S_IFLNK}
    };

    if (directory_contains_only(probe_fd, root_entries,
                                sizeof(root_entries) / sizeof(root_entries[0])) != 0 ||
        reconcile_probe_operand_directory(
            probe_fd, "live", live_entries,
            sizeof(live_entries) / sizeof(live_entries[0])) != 0 ||
        reconcile_probe_operand_directory(
            probe_fd, "private", private_entries,
            sizeof(private_entries) / sizeof(private_entries[0])) != 0) {
        return -1;
    }
    return 0;
}

static int open_probe_namespace(int base_fd)
{
    int probe_fd;

    if (mkdirat(base_fd, PROBE_NAMESPACE, 0700) != 0 && errno != EEXIST) {
        perror("dcentos-deploy-path: create probe namespace");
        return -1;
    }
    probe_fd = openat(base_fd, PROBE_NAMESPACE,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (probe_fd < 0 || require_private_directory(probe_fd) != 0) {
        if (probe_fd >= 0) {
            (void)close(probe_fd);
        }
        return -1;
    }
    return probe_fd;
}

static int lock_probe_namespace(int probe_fd)
{
    struct stat metadata;
    int lock_fd;

    lock_fd = openat(probe_fd, PROBE_LOCK,
                     O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                     0600);
    if (lock_fd < 0 || fstat(lock_fd, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 07777) != 0600 || metadata.st_nlink != 1 ||
        flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        if (lock_fd >= 0) {
            (void)close(lock_fd);
        }
        return -1;
    }
    return lock_fd;
}

#ifdef DCENTOS_DEPLOY_PATH_TEST_FAILPOINTS
static void pause_probe_after_sync_for_test(void)
{
    const char *marker = getenv("DCENTOS_DEPLOY_PATH_TEST_PAUSE_AFTER_SYNC");
    static const char ready[] = "ready\n";
    int marker_fd;

    if (marker == NULL || marker[0] != '/') {
        return;
    }
    marker_fd = open(marker,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     0600);
    if (marker_fd < 0 ||
        write(marker_fd, ready, sizeof(ready) - 1U) !=
            (ssize_t)(sizeof(ready) - 1U) ||
        fsync(marker_fd) != 0 || close(marker_fd) != 0) {
        _exit(EX_UNAVAILABLE);
    }
    for (;;) {
        (void)pause();
    }
}
#endif

static int probe_directory(const char *path)
{
    struct stat source;
    struct stat destination;
    int base_fd = -1;
    int probe_fd = -1;
    int lock_fd = -1;
    int live_fd = -1;
    int private_fd = -1;
    int result = -1;

    if (path == NULL || path[0] != '/') {
        fprintf(stderr,
                "dcentos-deploy-path: probe directory must be absolute\n");
        return -1;
    }
    base_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (base_fd < 0) {
        perror("dcentos-deploy-path: open probe filesystem");
        goto out;
    }
    probe_fd = open_probe_namespace(base_fd);
    if (probe_fd < 0) {
        goto out;
    }
    lock_fd = lock_probe_namespace(probe_fd);
    if (lock_fd < 0 || reconcile_probe_namespace(probe_fd) != 0 ||
        syncfs(probe_fd) != 0) {
        goto out;
    }
    if (mkdirat(probe_fd, "live", 0700) != 0 ||
        mkdirat(probe_fd, "private", 0700) != 0) {
        perror("dcentos-deploy-path: create probe operand directories");
        goto out;
    }
    live_fd = openat(probe_fd, "live",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    private_fd = openat(probe_fd, "private",
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (live_fd < 0 || private_fd < 0 ||
        require_private_directory(live_fd) != 0 ||
        require_private_directory(private_fd) != 0) {
        goto out;
    }
    if (create_probe_file(live_fd, "regular-source") != 0 ||
        create_probe_file(live_fd, "collision") != 0 ||
        symlinkat("dcentos-probe-target", private_fd, "symlink-source") != 0) {
        perror("dcentos-deploy-path: create probe objects");
        goto out;
    }
    if (retire_at(live_fd, "regular-source",
                  private_fd, "regular-retired") != 0 ||
        restore_link_at(private_fd, "regular-retired",
                        live_fd, "regular-restored") != 0 ||
        restore_link_at(private_fd, "symlink-source",
                        live_fd, "symlink-restored") != 0) {
        goto out;
    }
    if (linkat(private_fd, "regular-retired",
               live_fd, "collision", 0) == 0 || errno != EEXIST) {
        fprintf(stderr,
                "dcentos-deploy-path: filesystem did not enforce no-clobber link semantics\n");
        goto out;
    }
    if (fstatat(private_fd, "symlink-source", &source,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        fstatat(live_fd, "symlink-restored", &destination,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISLNK(source.st_mode) || !same_object(&source, &destination)) {
        fprintf(stderr,
                "dcentos-deploy-path: symlink-object hard-link probe failed\n");
        goto out;
    }
    if (syncfs(probe_fd) != 0) {
        perror("dcentos-deploy-path: sync probe filesystem");
        goto out;
    }
#ifdef DCENTOS_DEPLOY_PATH_TEST_FAILPOINTS
    pause_probe_after_sync_for_test();
#endif
    result = 0;

out:
    if (live_fd >= 0) {
        if (close(live_fd) != 0) {
            result = -1;
        }
    }
    if (private_fd >= 0) {
        if (close(private_fd) != 0) {
            result = -1;
        }
    }
    if (probe_fd >= 0) {
        if (lock_fd >= 0 && reconcile_probe_namespace(probe_fd) != 0) {
            result = -1;
        }
        if (lock_fd >= 0 && syncfs(probe_fd) != 0) {
            result = -1;
        }
        if (lock_fd >= 0 && close(lock_fd) != 0) {
            result = -1;
        }
        if (close(probe_fd) != 0) {
            result = -1;
        }
    }
    if (base_fd >= 0 && close(base_fd) != 0) {
        result = -1;
    }
    return result;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "probe") == 0) {
        return probe_directory(argv[2]) == 0 ? 0 : EX_UNAVAILABLE;
    }
    if (argc == 4 &&
        (strcmp(argv[1], "retire") == 0 ||
         strcmp(argv[1], "restore-link") == 0)) {
        return run_path_operation(argv[1], argv[2], argv[3]) == 0
                   ? 0
                   : EX_UNAVAILABLE;
    }
    fprintf(stderr,
            "Usage: %s probe DIRECTORY\n"
            "       %s retire SOURCE DESTINATION\n"
            "       %s restore-link SOURCE DESTINATION\n",
            argv[0], argv[0], argv[0]);
    return EX_USAGE;
}
