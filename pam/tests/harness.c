/* harness <service> <user> <password|-> [answer ...]
 * Runs pam_authenticate for the service through the real PAM stack. Answers feed the hidden prompts in order; messages are
 * printed as INFO lines. Exit 0 on PAM_SUCCESS, 1 on any other result. */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char **answers; int n, i; } script;

static int conv(int num, const struct pam_message **msg, struct pam_response **resp, void *data) {
  script *s = data;
  struct pam_response *r = calloc((size_t)num, sizeof *r);
  if (!r) return PAM_BUF_ERR;
  for (int k = 0; k < num; k++) {
    switch (msg[k]->msg_style) {
      case PAM_TEXT_INFO: case PAM_ERROR_MSG: printf("INFO:%s\n", msg[k]->msg); break;
      case PAM_PROMPT_ECHO_OFF: case PAM_PROMPT_ECHO_ON:
        printf("PROMPT:%s\n", msg[k]->msg);
        if (s->i >= s->n) { free(r); return PAM_CONV_ERR; }
        r[k].resp = strdup(s->answers[s->i++]);
        break;
      default: free(r); return PAM_CONV_ERR;
    }
  }
  *resp = r;
  return PAM_SUCCESS;
}

int main(int argc, char **argv) {
  if (argc < 4) { fprintf(stderr, "usage: harness service user password|- [answers...]\n"); return 2; }
  script s = {.answers = argv + 4, .n = argc - 4};
  struct pam_conv c = {conv, &s};
  pam_handle_t *h = NULL;
  int rc = pam_start(argv[1], argv[2], &c, &h);
  if (rc != PAM_SUCCESS) { printf("RESULT start=%d\n", rc); return 1; }
  if (strcmp(argv[3], "-") != 0) pam_set_item(h, PAM_AUTHTOK, argv[3]);
  rc = pam_authenticate(h, 0);
  printf("RESULT %d\n", rc);
  pam_end(h, rc);
  return rc == PAM_SUCCESS ? 0 : 1;
}
