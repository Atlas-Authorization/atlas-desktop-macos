/* Atlas PAM step: the conversation logic, free of PAM and of the operating system so it can be unit-tested.
 *
 * pam_atlas.so talks to the Atlas agent helper (atlas-pam-helper, which runs the same LoginGate as the login-window plugin:
 * same config, same offline bundle, same break-glass accounts) over a line protocol on a pipe:
 *
 *   module -> helper            helper -> module
 *   BEGIN <user> <service>      ALLOW <text> | DENY <text> | CHALLENGE online=0|1 push=0|1 totp=0|1 offline=0|1 pin=0|1
 *   PUSH                        NUMBER <digits>, then OK | REJECT <text> | UNREACHABLE
 *   CODE <6 digits>             OK | RETRY <text> | REJECT <text> | LOCKED | UNREACHABLE
 *   OFFLINE <pin|-> <6 digits>  OK | RETRY <text> | REJECT <text> | LOCKED
 *   QUIT
 *
 * Anything unexpected, a timeout or a closed pipe is a refusal. */
#ifndef ATLAS_PAM_CORE_H
#define ATLAS_PAM_CORE_H

#include <stddef.h>

#define ATLAS_LINE_MAX 256

typedef enum {
  ATLAS_R_BAD = 0,
  ATLAS_R_ALLOW,
  ATLAS_R_DENY,
  ATLAS_R_CHALLENGE,
  ATLAS_R_NUMBER,
  ATLAS_R_OK,
  ATLAS_R_RETRY,
  ATLAS_R_REJECT,
  ATLAS_R_UNREACHABLE,
  ATLAS_R_LOCKED
} atlas_reply_kind;

typedef struct {
  atlas_reply_kind kind;
  char text[ATLAS_LINE_MAX]; /* sanitised: printable ASCII only */
  int online, push, totp, offline, pin;
} atlas_reply;

/* Parses one helper line (no trailing newline). Returns 0 on success; on failure out->kind is ATLAS_R_BAD. */
int atlas_parse_reply(const char *line, atlas_reply *out);

/* Local account names: 1-63 of [A-Za-z0-9._-], not starting with '-'. Rejects anything that could break the line protocol. */
int atlas_valid_user(const char *s);
int atlas_valid_service(const char *s);
int atlas_valid_code(const char *s); /* exactly 6 digits */
int atlas_valid_pin(const char *s);  /* 6 to 12 digits */

/* Overwrites a secret in a way the compiler may not drop. */
void atlas_wipe(void *p, size_t n);

typedef struct {
  void *ctx;
  int (*send)(void *ctx, const char *line);                      /* 0 ok */
  int (*recv)(void *ctx, char *buf, size_t n, int timeout_ms);   /* 0 ok, -1 timeout / EOF / error */
  void (*info)(void *ctx, const char *msg);
  int (*prompt)(void *ctx, const char *msg, int echo, char *buf, size_t n); /* 0 ok, -1 cancelled */
} atlas_io;

/* Overridable at build time so the integration tests can exercise the timeouts in milliseconds. */
#ifndef ATLAS_BEGIN_TIMEOUT_MS
#define ATLAS_BEGIN_TIMEOUT_MS 45000
#endif
#ifndef ATLAS_PUSH_TIMEOUT_MS
#define ATLAS_PUSH_TIMEOUT_MS 130000
#endif
#ifndef ATLAS_CODE_TIMEOUT_MS
#define ATLAS_CODE_TIMEOUT_MS 35000
#endif
#define ATLAS_MAX_TRIES 3

/* Runs the whole step. Returns 1 when the account may continue, 0 otherwise (the caller maps 0 to PAM_AUTH_ERR). */
int atlas_authenticate(const atlas_io *io, const char *user, const char *service);

#endif
