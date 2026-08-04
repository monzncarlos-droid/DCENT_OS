/*
 * dcentos-deploy-lock - kernel-lifetime command exclusion for dcentrald.
 *
 * Copyright (C) 2026 D-Central Technologies
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#error "dcentos-deploy-lock requires O_CLOEXEC"
#endif
#ifndef O_NOFOLLOW
#error "dcentos-deploy-lock requires O_NOFOLLOW"
#endif

#ifndef DCENTOS_DEPLOY_LOCK_PATH
#define DCENTOS_DEPLOY_LOCK_PATH "/run/dcentos-deploy-admission.lock"
#endif

#define EX_USAGE 64
#define EX_UNAVAILABLE 69
#define EX_TEMPFAIL 75

static volatile sig_atomic_t child_pid = -1;

static int descriptor_from_environment(const char *name)
{
    const char *value = getenv(name);
    char *end = NULL;
    long parsed;

    if (value == NULL || *value == '\0') {
        return -1;
    }
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < 3 ||
        parsed > 1024) {
        return -1;
    }
    return (int)parsed;
}

static int publish_handoff_ready(void)
{
    const char marker = 'R';
    int fd = descriptor_from_environment("DCENTOS_DEPLOY_LOCK_READY_FD");
    int inherited_lock_fd =
        descriptor_from_environment("DCENTOS_DEPLOY_LOCK_FD");
    ssize_t written;

    if (fd < 0 || inherited_lock_fd < 0) {
        fprintf(stderr, "dcentos-deploy-lock: no valid handoff descriptors\n");
        return EX_UNAVAILABLE;
    }
    /* flock is scoped to the shared open-file description. Unlocking this
     * inherited duplicate atomically releases every wrapper/descendant copy
     * only after the admitted child has been proven. */
    if (flock(inherited_lock_fd, LOCK_UN) != 0) {
        perror("dcentos-deploy-lock: handoff unlock");
        return EX_UNAVAILABLE;
    }
    do {
        written = write(fd, &marker, sizeof(marker));
    } while (written < 0 && errno == EINTR);
    if (written != (ssize_t)sizeof(marker) || close(fd) != 0 ||
        close(inherited_lock_fd) != 0) {
        perror("dcentos-deploy-lock: publish handoff");
        return EX_UNAVAILABLE;
    }
    return 0;
}

static void forward_signal(int signo)
{
    pid_t pid = (pid_t)child_pid;

    if (pid > 0) {
        (void)kill(pid, signo);
    }
}

static int install_signal_handlers(void)
{
    struct sigaction action;
    int signals[] = {SIGHUP, SIGINT, SIGTERM};
    size_t i;

    memset(&action, 0, sizeof(action));
    action.sa_handler = forward_signal;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    for (i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
        if (sigaction(signals[i], &action, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static int deployment_signal_mask(sigset_t *mask)
{
    if (sigemptyset(mask) != 0 || sigaddset(mask, SIGHUP) != 0 ||
        sigaddset(mask, SIGINT) != 0 || sigaddset(mask, SIGTERM) != 0) {
        return -1;
    }
    return 0;
}

static int reset_child_signal_handlers(void)
{
    struct sigaction action;
    int signals[] = {SIGHUP, SIGINT, SIGTERM};
    size_t i;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    for (i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
        if (sigaction(signals[i], &action, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static int unblock_child_signals(void)
{
    sigset_t empty_mask;

    if (sigemptyset(&empty_mask) != 0 ||
        sigprocmask(SIG_SETMASK, &empty_mask, NULL) != 0) {
        return -1;
    }
    return 0;
}

static int exec_with_parent_death_signal(pid_t expected_parent, char **command)
{
#ifdef DCENTOS_DEPLOY_LOCK_TEST_PARENT_DEATH_PRECHECK_USEC
    (void)usleep(DCENTOS_DEPLOY_LOCK_TEST_PARENT_DEATH_PRECHECK_USEC);
#endif

    if (getppid() != expected_parent || reset_child_signal_handlers() != 0 ||
        unblock_child_signals() != 0 ||
        prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
        getppid() != expected_parent) {
        return EX_UNAVAILABLE;
    }
    execvp(command[0], command);
    perror("dcentos-deploy-lock: parent-death execvp");
    return errno == ENOENT ? 127 : 126;
}

static int open_validated_lock(void)
{
    struct stat opened;
    struct stat named;
    int fd;
#ifdef DCENTOS_DEPLOY_LOCK_TEST_ALLOW_NONROOT
    uid_t expected_uid = geteuid();
    gid_t expected_gid = getegid();
#else
    uid_t expected_uid = 0;
    gid_t expected_gid = 0;
#endif

    fd = open(DCENTOS_DEPLOY_LOCK_PATH,
              O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
              S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("dcentos-deploy-lock: open");
        return -1;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0 || fstat(fd, &opened) != 0) {
        perror("dcentos-deploy-lock: validate opened lock");
        close(fd);
        return -1;
    }
    if (!S_ISREG(opened.st_mode) || opened.st_uid != expected_uid ||
        opened.st_gid != expected_gid ||
        opened.st_nlink != 1 || (opened.st_mode & 07777) != 0600) {
        fprintf(stderr, "dcentos-deploy-lock: unsafe lock metadata\n");
        close(fd);
        return -1;
    }
    if (lstat(DCENTOS_DEPLOY_LOCK_PATH, &named) != 0 ||
        !S_ISREG(named.st_mode) || named.st_dev != opened.st_dev ||
        named.st_ino != opened.st_ino || named.st_nlink != 1) {
        fprintf(stderr, "dcentos-deploy-lock: lock pathname identity changed\n");
        close(fd);
        return -1;
    }
    return fd;
}

static int wait_for_child(pid_t pid)
{
    int status;
    pid_t waited;

    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    child_pid = -1;
    if (waited < 0) {
        perror("dcentos-deploy-lock: waitpid");
        return EX_UNAVAILABLE;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return EX_UNAVAILABLE;
}

int main(int argc, char **argv)
{
    bool handoff = false;
    pid_t parent;
    pid_t pid;
    int lock_fd;
    int ready_pipe[2] = {-1, -1};
    sigset_t deployment_signals;
    sigset_t original_signal_mask;
    char ready_fd_text[32];
    char lock_fd_text[32];
    char ready_marker = '\0';
    ssize_t ready_result;
    char *expected_parent_end = NULL;
    long expected_parent_long;

    if (argc == 2 && strcmp(argv[1], "--ready") == 0) {
        return publish_handoff_ready();
    }
    if (argc < 3 ||
        (strcmp(argv[1], "--") != 0 &&
         strcmp(argv[1], "--handoff") != 0 &&
         strcmp(argv[1], "--parent-death-signal") != 0)) {
        fprintf(stderr,
                "Usage: %s {-- command [args...]|--handoff command [args...]|--parent-death-signal expected-parent-pid -- command [args...]|--ready}\n",
                argv[0]);
        return EX_USAGE;
    }
#ifndef DCENTOS_DEPLOY_LOCK_TEST_ALLOW_NONROOT
    if (geteuid() != 0 || getegid() != 0) {
        fprintf(stderr, "dcentos-deploy-lock: root identity required\n");
        return EX_UNAVAILABLE;
    }
#endif
    if (strcmp(argv[1], "--parent-death-signal") == 0) {
        if (argc < 5 || strcmp(argv[3], "--") != 0) {
            return EX_USAGE;
        }
        errno = 0;
        expected_parent_long = strtol(argv[2], &expected_parent_end, 10);
        if (errno != 0 || expected_parent_end == argv[2] ||
            *expected_parent_end != '\0' || expected_parent_long <= 1 ||
            (long)(pid_t)expected_parent_long != expected_parent_long) {
            return EX_USAGE;
        }
        return exec_with_parent_death_signal((pid_t)expected_parent_long,
                                             &argv[4]);
    }
    handoff = strcmp(argv[1], "--handoff") == 0;

    lock_fd = open_validated_lock();
    if (lock_fd < 0) {
        return EX_UNAVAILABLE;
    }
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        int saved_errno = errno;
        close(lock_fd);
        if (saved_errno == EWOULDBLOCK || saved_errno == EAGAIN) {
            return EX_TEMPFAIL;
        }
        errno = saved_errno;
        perror("dcentos-deploy-lock: flock");
        return EX_UNAVAILABLE;
    }
    if (deployment_signal_mask(&deployment_signals) != 0 ||
        sigprocmask(SIG_BLOCK, &deployment_signals, &original_signal_mask) !=
            0) {
        perror("dcentos-deploy-lock: block signals");
        close(lock_fd);
        return EX_UNAVAILABLE;
    }
    if (install_signal_handlers() != 0) {
        perror("dcentos-deploy-lock: sigaction");
        (void)sigprocmask(SIG_SETMASK, &original_signal_mask, NULL);
        close(lock_fd);
        return EX_UNAVAILABLE;
    }
    if (handoff && pipe2(ready_pipe, O_CLOEXEC) != 0) {
        perror("dcentos-deploy-lock: pipe2");
        (void)sigprocmask(SIG_SETMASK, &original_signal_mask, NULL);
        close(lock_fd);
        return EX_UNAVAILABLE;
    }

    parent = getpid();
    pid = fork();
    if (pid < 0) {
        perror("dcentos-deploy-lock: fork");
        (void)sigprocmask(SIG_SETMASK, &original_signal_mask, NULL);
        close(lock_fd);
        return EX_UNAVAILABLE;
    }
    if (pid == 0) {
        int lock_flags = fcntl(lock_fd, F_GETFD);

        if (reset_child_signal_handlers() != 0) {
            _exit(EX_UNAVAILABLE);
        }
        if (lock_flags < 0 ||
            fcntl(lock_fd, F_SETFD, lock_flags & ~FD_CLOEXEC) != 0) {
            _exit(EX_UNAVAILABLE);
        }
        if (handoff) {
            int flags;

            (void)close(ready_pipe[0]);
            flags = fcntl(ready_pipe[1], F_GETFD);
            if (flags < 0 ||
                fcntl(ready_pipe[1], F_SETFD, flags & ~FD_CLOEXEC) != 0) {
                _exit(EX_UNAVAILABLE);
            }
            (void)snprintf(ready_fd_text, sizeof(ready_fd_text), "%d",
                           ready_pipe[1]);
            if (setenv("DCENTOS_DEPLOY_LOCK_READY_FD", ready_fd_text, 1) != 0) {
                _exit(EX_UNAVAILABLE);
            }
            (void)snprintf(lock_fd_text, sizeof(lock_fd_text), "%d", lock_fd);
            if (setenv("DCENTOS_DEPLOY_LOCK_FD", lock_fd_text, 1) != 0) {
                _exit(EX_UNAVAILABLE);
            }
        }
#ifdef DCENTOS_DEPLOY_LOCK_TEST_PRE_PDEATHSIG_USEC
        (void)usleep(DCENTOS_DEPLOY_LOCK_TEST_PRE_PDEATHSIG_USEC);
#endif
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent) {
            _exit(EX_UNAVAILABLE);
        }
        if (sigprocmask(SIG_SETMASK, &original_signal_mask, NULL) != 0) {
            _exit(EX_UNAVAILABLE);
        }
        execvp(argv[2], &argv[2]);
        perror("dcentos-deploy-lock: execvp");
        _exit(errno == ENOENT ? 127 : 126);
    }

    child_pid = (sig_atomic_t)pid;
    if (sigprocmask(SIG_SETMASK, &original_signal_mask, NULL) != 0) {
        perror("dcentos-deploy-lock: restore signals");
        (void)kill(pid, SIGKILL);
        (void)wait_for_child(pid);
        close(lock_fd);
        return EX_UNAVAILABLE;
    }
    if (handoff) {
        (void)close(ready_pipe[1]);
        do {
            ready_result = read(ready_pipe[0], &ready_marker,
                                sizeof(ready_marker));
        } while (ready_result < 0 && errno == EINTR);
        (void)close(ready_pipe[0]);
        if (ready_result < 0) {
            perror("dcentos-deploy-lock: handoff read");
            (void)kill(pid, SIGTERM);
            (void)wait_for_child(pid);
            close(lock_fd);
            return EX_UNAVAILABLE;
        }
        if (ready_result == 1 && ready_marker != 'R') {
            fprintf(stderr, "dcentos-deploy-lock: invalid handoff marker\n");
            (void)kill(pid, SIGTERM);
            (void)wait_for_child(pid);
            close(lock_fd);
            return EX_UNAVAILABLE;
        }
        /* EOF without a marker means the command and every inheriting child
         * closed the handoff descriptor. Releasing is then process-tree safe. */
        close(lock_fd);
        lock_fd = -1;
    }
    return wait_for_child(pid);
}
