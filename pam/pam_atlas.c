/* pam_atlas.so: the Atlas second-factor step for PAM services (sshd, su, sudo, screensharing, ...).
 *
 * Put it after the password module:   auth  required  /usr/local/lib/pam/pam_atlas.so
 * It re-checks the password the earlier module collected against OpenDirectory (so a wrong password never starts a push),
 * then asks the Atlas agent helper to run the same gate as the login window: same config, same offline bundle, same
 * break-glass accounts. Every failure refuses. */
#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "atlas_pam_core.h"

#ifdef ATLAS_PAM_TESTING
/* The test build (never installed) swaps the two things that need a real account and a real helper. */
#define HELPER_PATH_DEFAULT "/nonexistent"
#else
#define HELPER_PATH_DEFAULT "/usr/local/libexec/atlas/atlas-pam-helper"
#endif
#define KILL_SWITCH "/Library/Application Support/Atlas/pam-disabled"

typedef struct {
  pam_handle_t *pamh;
  int in_fd, out_fd; /* to / from the helper */
  char buf[1024];
  size_t have;
} session;

static int write_all(int fd, const char *s, size_t n) {
  while (n) {
    ssize_t w = write(fd, s, n);
    if (w < 0) { if (errno == EINTR) continue; return -1; }
    s += w; n -= (size_t)w;
  }
  return 0;
}

static int io_send(void *ctx, const char *line) {
  session *s = ctx;
  size_t n = strlen(line);
  if (n + 1 >= ATLAS_LINE_MAX) return -1;
  return write_all(s->out_fd, line, n) || write_all(s->out_fd, "\n", 1) ? -1 : 0;
}

static int io_recv(void *ctx, char *buf, size_t n, int timeout_ms) {
  session *s = ctx;
  for (;;) {
    char *nl = memchr(s->buf, '\n', s->have);
    if (nl) {
      size_t len = (size_t)(nl - s->buf);
      if (len >= n) return -1;
      memcpy(buf, s->buf, len);
      buf[len] = 0;
      memmove(s->buf, nl + 1, s->have - len - 1);
      s->have -= len + 1;
      return 0;
    }
    if (s->have >= sizeof s->buf) return -1;
    struct pollfd p = {.fd = s->in_fd, .events = POLLIN};
    int r = poll(&p, 1, timeout_ms);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) return -1; /* timeout or error */
    ssize_t got = read(s->in_fd, s->buf + s->have, sizeof s->buf - s->have);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) return -1; /* EOF: the helper died */
    s->have += (size_t)got;
  }
}

static void converse(pam_handle_t *pamh, int style, const char *msg, char *reply, size_t n) {
  const struct pam_conv *conv = NULL;
  if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || !conv || !conv->conv) return;
  struct pam_message m = {.msg_style = style, .msg = (char *)msg}; /* the conversation does not modify it */
  const struct pam_message *mp = &m;
  struct pam_response *resp = NULL;
  if (conv->conv(1, &mp, &resp, conv->appdata_ptr) == PAM_SUCCESS && resp) {
    if (reply && resp[0].resp) { strncpy(reply, resp[0].resp, n - 1); reply[n - 1] = 0; }
    if (resp[0].resp) { atlas_wipe(resp[0].resp, strlen(resp[0].resp)); free(resp[0].resp); }
    free(resp);
  } else if (reply) {
    reply[0] = 0;
  }
}

static void io_info(void *ctx, const char *msg) { converse(((session *)ctx)->pamh, PAM_TEXT_INFO, msg, NULL, 0); }

static int io_prompt(void *ctx, const char *msg, int echo, char *buf, size_t n) {
  buf[0] = 0;
  converse(((session *)ctx)->pamh, echo ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF, msg, buf, n);
  return buf[0] ? 0 : -1; /* an empty answer cancels */
}

/* The helper holds the offline bundle path to the System keychain, so it must be ours: root-owned, not writable by others,
 * in a root-owned directory. */
#ifndef ATLAS_PAM_TESTING
static int trusted(const char *path) {
  struct stat st;
  if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) || !(st.st_mode & S_IXUSR)) return 0;
  char dir[1024];
  strncpy(dir, path, sizeof dir - 1);
  dir[sizeof dir - 1] = 0;
  char *slash = strrchr(dir, '/');
  if (!slash) return 0;
  *slash = 0;
  return stat(dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 && !(st.st_mode & (S_IWGRP | S_IWOTH));
}
#endif

#ifdef ATLAS_PAM_TESTING
static int verify_password(const char *user, const char *pw) { (void)user; return strcmp(pw, "atlas-test-password") == 0; }
#else
static int verify_password(const char *user, const char *pw) {
  int ok = 0;
  CFStringRef cu = CFStringCreateWithCString(NULL, user, kCFStringEncodingUTF8);
  CFStringRef cp = CFStringCreateWithCString(NULL, pw, kCFStringEncodingUTF8);
  if (cu && cp) {
    ODNodeRef node = ODNodeCreateWithNodeType(NULL, kODSessionDefault, kODNodeTypeAuthentication, NULL);
    if (node) {
      ODRecordRef rec = ODNodeCopyRecord(node, kODRecordTypeUsers, cu, NULL, NULL);
      if (rec) { ok = ODRecordVerifyPassword(rec, cp, NULL) ? 1 : 0; CFRelease(rec); }
      CFRelease(node);
    }
  }
  if (cu) CFRelease(cu);
  if (cp) CFRelease(cp);
  return ok;
}
#endif

static int kill_switch_on(void) {
  struct stat st;
  return lstat(KILL_SWITCH, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 && !(st.st_mode & (S_IWGRP | S_IWOTH));
}

static void wait_child(pid_t pid) {
  for (int i = 0; i < 20; i++) {
    int st;
    pid_t r = waitpid(pid, &st, WNOHANG);
    if (r == pid || (r < 0 && errno != EINTR)) return;
    usleep(50000);
  }
  kill(pid, SIGKILL);
  int st;
  waitpid(pid, &st, 0);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void)flags; (void)argc; (void)argv;
  const char *user = NULL, *service = NULL, *pw = NULL;
  if (kill_switch_on()) {
    syslog(LOG_AUTHPRIV | LOG_WARNING, "pam_atlas: kill switch present, Atlas step skipped");
    return PAM_IGNORE;
  }
  if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !atlas_valid_user(user)) return PAM_AUTH_ERR;
  if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS || !atlas_valid_service(service)) return PAM_AUTH_ERR;
  /* The password the earlier module collected. Without one (a smart card, say) we have nothing to check and refuse. */
  if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pw) != PAM_SUCCESS || !pw || !*pw) {
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "pam_atlas: no password from an earlier module for %s (%s); refused", user, service);
    return PAM_AUTH_ERR;
  }
  if (!verify_password(user, pw)) return PAM_AUTH_ERR; /* a wrong password never reaches Atlas */

  const char *helper = HELPER_PATH_DEFAULT;
#ifdef ATLAS_PAM_TESTING
  if (getenv("ATLAS_PAM_HELPER")) helper = getenv("ATLAS_PAM_HELPER");
#else
  if (!trusted(helper)) {
    syslog(LOG_AUTHPRIV | LOG_ERR, "pam_atlas: helper %s missing or not root-owned; refused", helper);
    return PAM_AUTH_ERR;
  }
#endif

  int to[2], from[2];
  if (pipe(to) != 0) return PAM_AUTH_ERR;
  if (pipe(from) != 0) { close(to[0]); close(to[1]); return PAM_AUTH_ERR; }
  posix_spawn_file_actions_t fa;
  posix_spawnattr_t at;
  posix_spawn_file_actions_init(&fa);
  posix_spawnattr_init(&at);
  posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF);
  sigset_t all;
  sigfillset(&all);
  posix_spawnattr_setsigdefault(&at, &all);
  posix_spawn_file_actions_adddup2(&fa, to[0], 0);
  posix_spawn_file_actions_adddup2(&fa, from[1], 1);
  posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
  char *args[] = {(char *)helper, (char *)"serve", NULL};
  char *env[] = {(char *)"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
  pid_t pid = 0;
  int rc = posix_spawn(&pid, helper, &fa, &at, args, env);
  posix_spawn_file_actions_destroy(&fa);
  posix_spawnattr_destroy(&at);
  close(to[0]);
  close(from[1]);
  if (rc != 0) {
    syslog(LOG_AUTHPRIV | LOG_ERR, "pam_atlas: cannot start the helper (%d); refused", rc);
    close(to[1]);
    close(from[0]);
    return PAM_AUTH_ERR;
  }
  /* A dead helper must not kill the host process (sshd, sudo): no SIGPIPE, just a failed write. */
  fcntl(to[1], F_SETNOSIGPIPE, 1);
  fcntl(to[1], F_SETFD, FD_CLOEXEC);
  fcntl(from[0], F_SETFD, FD_CLOEXEC);

  session s = {.pamh = pamh, .in_fd = from[0], .out_fd = to[1]};
  atlas_io io = {.ctx = &s, .send = io_send, .recv = io_recv, .info = io_info, .prompt = io_prompt};
  int allowed = atlas_authenticate(&io, user, service);
  io_send(&s, "QUIT");
  close(to[1]);
  close(from[0]);
  wait_child(pid);
  atlas_wipe(s.buf, sizeof s.buf);
  syslog(LOG_AUTHPRIV | (allowed ? LOG_INFO : LOG_NOTICE), "pam_atlas: %s for %s (%s)", allowed ? "allowed" : "refused", user, service);
  return allowed ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SERVICE_ERR;
}
