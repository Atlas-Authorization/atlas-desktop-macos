#include "atlas_pam_core.h"

#include <stdio.h>
#include <string.h>

static int is_digit(char c) { return c >= '0' && c <= '9'; }

static int all_digits(const char *s, size_t min, size_t max) {
  size_t n = strlen(s);
  if (n < min || n > max) return 0;
  for (size_t i = 0; i < n; i++)
    if (!is_digit(s[i])) return 0;
  return 1;
}

int atlas_valid_code(const char *s) { return s && all_digits(s, 6, 6); }
int atlas_valid_pin(const char *s) { return s && all_digits(s, 6, 12); }

static int name_ok(const char *s, size_t max) {
  if (!s || !*s || *s == '-') return 0;
  size_t n = strlen(s);
  if (n > max) return 0;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || is_digit(c) || c == '.' || c == '_' || c == '-';
    if (!ok) return 0;
  }
  return 1;
}
int atlas_valid_user(const char *s) { return name_ok(s, 63); }
int atlas_valid_service(const char *s) { return name_ok(s, 31); }

void atlas_wipe(void *p, size_t n) {
  volatile unsigned char *v = (volatile unsigned char *)p;
  while (n--) *v++ = 0;
}

static void sanitise(char *dst, size_t n, const char *src) {
  size_t j = 0;
  for (size_t i = 0; src[i] && j + 1 < n; i++) {
    unsigned char c = (unsigned char)src[i];
    dst[j++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
  }
  dst[j] = 0;
}

static int flag(const char *line, const char *key) {
  size_t k = strlen(key);
  for (const char *p = line; (p = strstr(p, key)) != NULL; p += k) {
    if ((p == line || p[-1] == ' ') && p[k] == '=') return p[k + 1] == '1';
  }
  return 0;
}

int atlas_parse_reply(const char *line, atlas_reply *out) {
  memset(out, 0, sizeof *out);
  out->kind = ATLAS_R_BAD;
  if (!line || strlen(line) >= ATLAS_LINE_MAX) return -1;
  static const struct { const char *tag; atlas_reply_kind kind; int hasText; } tags[] = {
      {"ALLOW", ATLAS_R_ALLOW, 1}, {"DENY", ATLAS_R_DENY, 1},       {"CHALLENGE", ATLAS_R_CHALLENGE, 0}, {"NUMBER", ATLAS_R_NUMBER, 1},
      {"OK", ATLAS_R_OK, 0},       {"RETRY", ATLAS_R_RETRY, 1},     {"REJECT", ATLAS_R_REJECT, 1},       {"UNREACHABLE", ATLAS_R_UNREACHABLE, 0},
      {"LOCKED", ATLAS_R_LOCKED, 0}};
  for (size_t i = 0; i < sizeof tags / sizeof tags[0]; i++) {
    size_t n = strlen(tags[i].tag);
    if (strncmp(line, tags[i].tag, n) != 0 || (line[n] != 0 && line[n] != ' ')) continue;
    const char *rest = line[n] == ' ' ? line + n + 1 : "";
    if (tags[i].kind == ATLAS_R_NUMBER && !all_digits(rest, 1, 4)) return -1; /* the number to match is 1-4 digits */
    if (tags[i].kind == ATLAS_R_CHALLENGE) {
      out->online = flag(rest, "online");
      out->push = flag(rest, "push");
      out->totp = flag(rest, "totp");
      out->offline = flag(rest, "offline");
      out->pin = flag(rest, "pin");
    } else if (tags[i].hasText) {
      sanitise(out->text, sizeof out->text, rest);
    }
    out->kind = tags[i].kind;
    return 0;
  }
  return -1;
}

static int xchg(const atlas_io *io, const char *cmd, int timeout_ms, atlas_reply *r) {
  char line[ATLAS_LINE_MAX];
  if (io->send(io->ctx, cmd) != 0) return -1;
  if (io->recv(io->ctx, line, sizeof line, timeout_ms) != 0) return -1;
  return atlas_parse_reply(line, r);
}

static int exchange_secret(const atlas_io *io, char *cmd, int timeout_ms, atlas_reply *r) {
  int rc = xchg(io, cmd, timeout_ms, r);
  atlas_wipe(cmd, strlen(cmd));
  return rc;
}

int atlas_authenticate(const atlas_io *io, const char *user, const char *service) {
  atlas_reply r;
  char cmd[ATLAS_LINE_MAX];
  if (!atlas_valid_user(user) || !atlas_valid_service(service)) return 0;
  snprintf(cmd, sizeof cmd, "BEGIN %s %s", user, service);
  if (xchg(io, cmd, ATLAS_BEGIN_TIMEOUT_MS, &r) != 0) return 0;
  if (r.kind == ATLAS_R_ALLOW) return 1;
  if (r.kind != ATLAS_R_CHALLENGE) {
    if (r.kind == ATLAS_R_DENY && r.text[0]) io->info(io->ctx, r.text);
    return 0;
  }

  int online = r.online, offline = r.offline, pin = r.pin;
  const int push = r.push, totp = r.totp;

  if (online && push) {
    if (xchg(io, "PUSH", ATLAS_BEGIN_TIMEOUT_MS, &r) != 0) return 0;
    if (r.kind == ATLAS_R_NUMBER) {
      char msg[ATLAS_LINE_MAX];
      snprintf(msg, sizeof msg, "Atlas: approve the sign-in on your phone and pick %s.", r.text);
      io->info(io->ctx, msg);
      char line[ATLAS_LINE_MAX];
      if (io->recv(io->ctx, line, sizeof line, ATLAS_PUSH_TIMEOUT_MS) != 0) return 0;
      if (atlas_parse_reply(line, &r) != 0) return 0;
      if (r.kind == ATLAS_R_OK) return 1;
      if (r.kind == ATLAS_R_UNREACHABLE) online = 0;
      else if (r.kind == ATLAS_R_REJECT) io->info(io->ctx, "Atlas: the push was not approved.");
      else return 0;
    } else if (r.kind == ATLAS_R_UNREACHABLE) {
      online = 0;
    } else if (r.kind != ATLAS_R_REJECT) {
      return 0; /* DENY, or a protocol violation */
    }
  }

  for (int tries = 0; tries < ATLAS_MAX_TRIES;) {
    char code[16] = {0}, pinbuf[32] = {0};
    if (online && totp) {
      if (io->prompt(io->ctx, "Atlas code: ", 0, code, sizeof code) != 0) return 0;
      if (!atlas_valid_code(code)) { atlas_wipe(code, sizeof code); io->info(io->ctx, "Atlas: enter the 6-digit code."); tries++; continue; }
      snprintf(cmd, sizeof cmd, "CODE %s", code);
      atlas_wipe(code, sizeof code);
      int rc = exchange_secret(io, cmd, ATLAS_CODE_TIMEOUT_MS, &r);
      if (rc != 0) return 0;
      if (r.kind == ATLAS_R_OK) return 1;
      if (r.kind == ATLAS_R_RETRY) { io->info(io->ctx, "Atlas: that code was not accepted."); tries++; continue; }
      if (r.kind == ATLAS_R_UNREACHABLE) { online = 0; continue; }
      return 0; /* REJECT, LOCKED, anything else */
    }
    if (!online && offline) {
      const char *pinArg = "-";
      if (pin) {
        if (io->prompt(io->ctx, "Atlas offline PIN: ", 0, pinbuf, sizeof pinbuf) != 0) return 0;
        if (!atlas_valid_pin(pinbuf)) { atlas_wipe(pinbuf, sizeof pinbuf); io->info(io->ctx, "Atlas: enter your 6 to 12 digit PIN."); tries++; continue; }
        pinArg = pinbuf;
      }
      if (io->prompt(io->ctx, "Atlas offline code: ", 0, code, sizeof code) != 0) { atlas_wipe(pinbuf, sizeof pinbuf); return 0; }
      if (!atlas_valid_code(code)) { atlas_wipe(code, sizeof code); atlas_wipe(pinbuf, sizeof pinbuf); io->info(io->ctx, "Atlas: enter the 6-digit code."); tries++; continue; }
      snprintf(cmd, sizeof cmd, "OFFLINE %s %s", pinArg, code);
      atlas_wipe(code, sizeof code);
      atlas_wipe(pinbuf, sizeof pinbuf);
      int rc = exchange_secret(io, cmd, ATLAS_CODE_TIMEOUT_MS, &r);
      if (rc != 0) return 0;
      if (r.kind == ATLAS_R_OK) return 1;
      if (r.kind == ATLAS_R_RETRY) { io->info(io->ctx, "Atlas: incorrect PIN or code."); tries++; continue; }
      return 0;
    }
    io->info(io->ctx, "Atlas: no second factor is available.");
    return 0;
  }
  return 0;
}
