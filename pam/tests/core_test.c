/* Unit tests for the conversation logic: no PAM, no helper, no root. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "atlas_pam_core.h"

static int failures = 0;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

/* A scripted peer: the helper's replies in order, the user's answers in order, and a record of what was sent / shown. */
typedef struct {
  const char *replies[16]; int nr, ri;
  const char *answers[8]; int na, ai;
  char sent[16][ATLAS_LINE_MAX]; int ns;
  char shown[16][ATLAS_LINE_MAX]; int nshown;
  char prompts[8][64]; int np;
  int sendFails;
} fake;

static int f_send(void *c, const char *line) {
  fake *f = c;
  if (f->sendFails) return -1;
  snprintf(f->sent[f->ns++], ATLAS_LINE_MAX, "%s", line);
  return 0;
}
static int f_recv(void *c, char *buf, size_t n, int t) {
  fake *f = c; (void)t;
  if (f->ri >= f->nr) return -1; /* timeout / EOF */
  snprintf(buf, n, "%s", f->replies[f->ri++]);
  return 0;
}
static void f_info(void *c, const char *m) { fake *f = c; snprintf(f->shown[f->nshown++], ATLAS_LINE_MAX, "%s", m); }
static int f_prompt(void *c, const char *m, int echo, char *buf, size_t n) {
  fake *f = c;
  snprintf(f->prompts[f->np++], 64, "%s", m);
  if (echo) return -1; /* the module never echoes a code or a PIN */
  if (f->ai >= f->na) return -1;
  snprintf(buf, n, "%s", f->answers[f->ai++]);
  return 0;
}
static atlas_io io_of(fake *f) { atlas_io io = {f, f_send, f_recv, f_info, f_prompt}; return io; }
#define RUN(f, ...) ({ atlas_io io_ = io_of(&(f)); atlas_authenticate(&io_, __VA_ARGS__); })

static void test_parse(void) {
  atlas_reply r;
  CHECK(atlas_parse_reply("ALLOW break-glass account", &r) == 0 && r.kind == ATLAS_R_ALLOW && !strcmp(r.text, "break-glass account"));
  CHECK(atlas_parse_reply("DENY device revoked", &r) == 0 && r.kind == ATLAS_R_DENY);
  CHECK(atlas_parse_reply("CHALLENGE online=1 push=1 totp=1 offline=0 pin=0", &r) == 0 && r.online && r.push && r.totp && !r.offline && !r.pin);
  CHECK(atlas_parse_reply("CHALLENGE online=0 offline=1 pin=1", &r) == 0 && !r.online && r.offline && r.pin);
  CHECK(atlas_parse_reply("CHALLENGE xonline=1 push=0", &r) == 0 && !r.online);               /* keys match whole words */
  CHECK(atlas_parse_reply("NUMBER 47", &r) == 0 && r.kind == ATLAS_R_NUMBER && !strcmp(r.text, "47"));
  CHECK(atlas_parse_reply("NUMBER 4x", &r) != 0 && r.kind == ATLAS_R_BAD);
  CHECK(atlas_parse_reply("NUMBER 12345", &r) != 0);
  CHECK(atlas_parse_reply("NUMBER", &r) != 0);
  CHECK(atlas_parse_reply("OK", &r) == 0 && r.kind == ATLAS_R_OK);
  CHECK(atlas_parse_reply("OKAY", &r) != 0);                                                   /* a tag is a whole word */
  CHECK(atlas_parse_reply("ok", &r) != 0);
  CHECK(atlas_parse_reply("", &r) != 0);
  CHECK(atlas_parse_reply("LOCKED", &r) == 0 && r.kind == ATLAS_R_LOCKED);
  CHECK(atlas_parse_reply("REJECT bad\x1b[31m", &r) == 0 && strchr(r.text, 0x1b) == NULL);   /* escape bytes never reach a terminal */
  char big[400]; memset(big, 'A', sizeof big); big[399] = 0;
  CHECK(atlas_parse_reply(big, &r) != 0);
}

static void test_valid(void) {
  CHECK(atlas_valid_user("alice") && atlas_valid_user("a.b_c-1") && atlas_valid_user("Admin2"));
  CHECK(!atlas_valid_user("") && !atlas_valid_user("-rf") && !atlas_valid_user("a b") && !atlas_valid_user("a\nQUIT") && !atlas_valid_user("a;b"));
  CHECK(!atlas_valid_user("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  CHECK(!atlas_valid_user(NULL) && !atlas_valid_service("") && atlas_valid_service("screensharing"));
  CHECK(atlas_valid_code("123456") && !atlas_valid_code("12345") && !atlas_valid_code("1234567") && !atlas_valid_code("12345a") && !atlas_valid_code(""));
  CHECK(atlas_valid_pin("123456") && atlas_valid_pin("123456789012") && !atlas_valid_pin("12345") && !atlas_valid_pin("1234567890123") && !atlas_valid_pin("12 456"));
  unsigned char b[4] = {1, 2, 3, 4};
  atlas_wipe(b, 4);
  CHECK(!b[0] && !b[1] && !b[2] && !b[3]);
}

static void test_allow_deny(void) {
  fake f = {.replies = {"ALLOW break-glass"}, .nr = 1};
  CHECK(RUN(f, "alice", "sudo") == 1);
  CHECK(f.ns == 1 && !strcmp(f.sent[0], "BEGIN alice sudo"));

  fake d = {.replies = {"DENY device revoked"}, .nr = 1};
  CHECK(RUN(d, "alice", "sshd") == 0 && d.nshown == 1 && strstr(d.shown[0], "revoked"));

  fake silent = {.nr = 0}; /* helper gone / timeout */
  CHECK(RUN(silent, "alice", "sshd") == 0);
  fake garbage = {.replies = {"hello"}, .nr = 1};
  CHECK(RUN(garbage, "alice", "sshd") == 0);
  fake wrongKind = {.replies = {"OK"}, .nr = 1}; /* OK is not an answer to BEGIN */
  CHECK(RUN(wrongKind, "alice", "sshd") == 0);
  fake nosend = {.replies = {"ALLOW x"}, .nr = 1, .sendFails = 1};
  CHECK(RUN(nosend, "alice", "sshd") == 0);

  fake bad = {.replies = {"ALLOW x"}, .nr = 1};
  CHECK(RUN(bad, "al ice", "sshd") == 0 && bad.ns == 0);     /* never sent: protocol injection */
  CHECK(RUN(bad, "alice", "bad service") == 0 && bad.ns == 0);
  CHECK(RUN(bad, "alice\nQUIT", "sudo") == 0 && bad.ns == 0);
}

static void test_push(void) {
  fake ok = {.replies = {"CHALLENGE online=1 push=1 totp=1 offline=0 pin=0", "NUMBER 47", "OK"}, .nr = 3};
  CHECK(RUN(ok, "alice", "sudo") == 1);
  CHECK(!strcmp(ok.sent[1], "PUSH") && ok.nshown == 1 && strstr(ok.shown[0], "47") && ok.np == 0);

  fake denied = {.replies = {"CHALLENGE online=1 push=1 totp=1 offline=0 pin=0", "NUMBER 12", "REJECT denied", "OK"}, .nr = 4, .answers = {"123456"}, .na = 1};
  CHECK(RUN(denied, "alice", "sudo") == 1);                       /* falls back to the code prompt */
  CHECK(denied.np == 1 && !strcmp(denied.sent[2], "CODE 123456"));

  fake pushOnly = {.replies = {"CHALLENGE online=1 push=1 totp=0 offline=0 pin=0", "NUMBER 12", "REJECT denied"}, .nr = 3};
  CHECK(RUN(pushOnly, "alice", "sudo") == 0);

  fake timeout = {.replies = {"CHALLENGE online=1 push=1 totp=1 offline=0 pin=0", "NUMBER 12"}, .nr = 2, .answers = {"123456"}, .na = 1};
  CHECK(RUN(timeout, "alice", "sudo") == 0);                      /* no answer to the push: not treated as a pass, not retried */

  fake noPush = {.replies = {"CHALLENGE online=1 push=1 totp=1 offline=0 pin=0", "DENY no push device", "OK"}, .nr = 3, .answers = {"123456"}, .na = 1};
  CHECK(RUN(noPush, "alice", "sudo") == 0);                      /* a DENY to PUSH is a refusal, not a fallback */

  fake odd = {.replies = {"CHALLENGE online=1 push=1 totp=1 offline=0 pin=0", "OK"}, .nr = 2, .answers = {"123456"}, .na = 1};
  CHECK(RUN(odd, "alice", "sudo") == 0);                          /* OK straight after PUSH skips the number: protocol violation */
}

static void test_code(void) {
  fake ok = {.replies = {"CHALLENGE online=1 push=0 totp=1 offline=0 pin=0", "OK"}, .nr = 2, .answers = {"123456"}, .na = 1};
  CHECK(RUN(ok, "alice", "su") == 1 && !strcmp(ok.sent[1], "CODE 123456"));
  CHECK(!strcmp(ok.prompts[0], "Atlas code: "));

  fake retry = {.replies = {"CHALLENGE online=1 push=0 totp=1 offline=0 pin=0", "RETRY wrong", "RETRY wrong", "OK"}, .nr = 4, .answers = {"111111", "222222", "333333"}, .na = 3};
  CHECK(RUN(retry, "alice", "su") == 1 && retry.ns == 4);

  fake three = {.replies = {"CHALLENGE online=1 push=0 totp=1 offline=0 pin=0", "RETRY", "RETRY", "RETRY", "OK"}, .nr = 5, .answers = {"1", "2", "3", "4"}, .na = 4};
  CHECK(RUN(three, "alice", "su") == 0);                           /* three tries and out; the fourth reply is never read */

  fake shape = {.replies = {"CHALLENGE online=1 push=0 totp=1 offline=0 pin=0", "OK"}, .nr = 2, .answers = {"12ab56", "654321"}, .na = 2};
  CHECK(RUN(shape, "alice", "su") == 1 && shape.ns == 2 && !strcmp(shape.sent[1], "CODE 654321")); /* a malformed code is never sent */

  fake cancel = {.replies = {"CHALLENGE online=1 push=0 totp=1 offline=0 pin=0"}, .nr = 1};
  CHECK(RUN(cancel, "alice", "su") == 0);

  fake locked = {.replies = {"CHALLENGE online=1 push=0 totp=1 offline=0 pin=0", "LOCKED", "OK"}, .nr = 3, .answers = {"123456", "123456"}, .na = 2};
  CHECK(RUN(locked, "alice", "su") == 0 && locked.ns == 2);
  fake reject = {.replies = {"CHALLENGE online=1 push=0 totp=1 offline=0 pin=0", "REJECT too many attempts"}, .nr = 2, .answers = {"123456"}, .na = 1};
  CHECK(RUN(reject, "alice", "su") == 0);
  fake none = {.replies = {"CHALLENGE online=1 push=0 totp=0 offline=0 pin=0"}, .nr = 1};
  CHECK(RUN(none, "alice", "su") == 0);                            /* nothing usable: refuse */
}

static void test_offline(void) {
  fake ok = {.replies = {"CHALLENGE online=0 push=0 totp=0 offline=1 pin=1", "OK"}, .nr = 2, .answers = {"24681357", "123456"}, .na = 2};
  CHECK(RUN(ok, "alice", "sshd") == 1 && !strcmp(ok.sent[1], "OFFLINE 24681357 123456"));

  fake nopin = {.replies = {"CHALLENGE online=0 push=0 totp=0 offline=1 pin=0", "OK"}, .nr = 2, .answers = {"123456"}, .na = 1};
  CHECK(RUN(nopin, "alice", "sshd") == 1 && !strcmp(nopin.sent[1], "OFFLINE - 123456"));

  fake badpin = {.replies = {"CHALLENGE online=0 push=0 totp=0 offline=1 pin=1", "OK"}, .nr = 2, .answers = {"12", "24681357", "123456"}, .na = 3};
  CHECK(RUN(badpin, "alice", "sshd") == 1);

  fake wrong = {.replies = {"CHALLENGE online=0 push=0 totp=0 offline=1 pin=1", "RETRY", "LOCKED"}, .nr = 3, .answers = {"24681357", "111111", "24681357", "111111"}, .na = 4};
  CHECK(RUN(wrong, "alice", "sshd") == 0);

  /* Online attempt that finds the server gone falls through to the offline factors. */
  fake drop = {.replies = {"CHALLENGE online=1 push=0 totp=1 offline=1 pin=0", "UNREACHABLE", "OK"}, .nr = 3, .answers = {"123456", "654321"}, .na = 2};
  CHECK(RUN(drop, "alice", "sshd") == 1 && !strcmp(drop.sent[2], "OFFLINE - 654321"));

  /* Offline is never offered while online, and never without a bundle. */
  fake onlineNoOffline = {.replies = {"CHALLENGE online=0 push=0 totp=0 offline=0 pin=0"}, .nr = 1};
  CHECK(RUN(onlineNoOffline, "alice", "sshd") == 0);
}

int main(void) {
  test_parse(); test_valid(); test_allow_deny(); test_push(); test_code(); test_offline();
  if (failures) { fprintf(stderr, "%d failure(s)\n", failures); return 1; }
  printf("pam core tests passed\n");
  return 0;
}
