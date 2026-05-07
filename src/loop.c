#include "loop.h"

#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

struct loopctx {
    int sigfd;
    int epfd;
};

/* handle SIGCHLD, nsproxy exits after all child processes exit
   returns:
   - -EAGAIN: child still alive
   - >= 0: exit status of last child
   - < 0: error
*/
static int sigfd_handler(struct loopctx *loop)
{
    struct signalfd_siginfo sig;
    pid_t pid;
    int stat, exited, exitcode = 0;

    if (read(loop->sigfd, &sig, sizeof(sig)) == -1)
        return -errno;

    /* we never add signals other than SIGCHLD to the sigmask,
       this should not happen */
    if (sig.ssi_signo != SIGCHLD)
        return -EINVAL;

    /* reap all exited children */
    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
        if (!WIFEXITED(stat) && !WIFSIGNALED(stat))
            continue; /* child not dead */
        exited = WIFEXITED(stat);
        exitcode = exited ? WEXITSTATUS(stat) : (128 + WTERMSIG(stat));
        loglv(1, "Child process %d %s %d", pid,
                 exited ? "exited with status" : "killed by signal",
                 exited ? WEXITSTATUS(stat) : WTERMSIG(stat));
    }

    /* no child could be reaped, may some still running, or all exited */

    if (pid == -1 && errno == ECHILD) {
        loglv(1, "All child exited, cleaning ...");
        return exitcode;
    } else if (pid == -1) {
        int ret = -errno;
        logwarn("sigfd_handler: waitpid() failed: %s", strerror(errno));
        return ret;
    } else {
        assert(pid == 0);
        return -EAGAIN;
    }
}

int loop_init(struct loopctx **loop, int sigfd)
{
    struct loopctx *p;
    struct epoll_event ev;

    if ((p = malloc(sizeof(struct loopctx))) == NULL)
        oom();

    if ((p->epfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        loglv(0, "loop_init: epoll_create1() failed: %s", strerror(errno));
        goto err_free_p;
    }

    p->sigfd = sigfd;
    ev.events = EPOLLIN;
    ev.data.ptr = &p->sigfd;
    if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, sigfd, &ev) == -1) {
        loglv(0, "loop_init: epoll_ctl(sigfd) failed: %s", strerror(errno));
        goto err_close_epfd;
    }

    loginfo("loop_init: initialized event loop (loopctx)");

    *loop = p;
    return 0;

err_close_epfd:
    close(p->epfd);
err_free_p:
    free(p);
    return -1;
}

void loop_deinit(struct loopctx *loop)
{
    close(loop->epfd);
    free(loop);
}

int loop_run(struct loopctx *loop)
{
    int i, nevent, ret;
    /* event polling and context switching is not the bottleneck,
       batch polling risks event caching pitfalls, see 'man 7 epoll' */
    struct epoll_event ev[1];

    for (;;) {
        if ((nevent = epoll_wait(loop->epfd, ev, arraysizeof(ev), -1)) == -1) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        for (i = 0; i < nevent; i++) {
            if (ev[i].data.ptr == &loop->sigfd) {
                if ((ret = sigfd_handler(loop)) != -EAGAIN)
                    return ret;
            } else {
                struct epcb_ops *epcb = ev[i].data.ptr;
                epcb->on_epoll_events(epcb, ev[i].events);
            }
        }
    }
}

int loop_epoll_ctl(struct loopctx *loop, int op, int fd, unsigned events,
                   struct epcb_ops *epcb)
{
    struct epoll_event ev;

    ev.events = events;
    ev.data.ptr = epcb;
    if (epoll_ctl(loop->epfd, op, fd, &ev) == -1) {
        int ret = -errno;
        if (errno == EEXIST) {
            logwarn("loop_epoll_ctl: fd %d is registered already", fd);
        } else if (errno == ENOENT) {
            logwarn("loop_epoll_ctl: fd %d is not registered", fd);
        } else {
            fprintf(stderr, "epoll_ctl(%d) failed: %s\n", op, strerror(errno));
            abort();
        }
        return ret;
    }

    return 0;
}
