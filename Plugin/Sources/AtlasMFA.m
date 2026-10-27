// Thin Objective-C shim: exports the PluginDescriptor symbol and forwards to Swift (atlas_mfa_run).
#import <Foundation/Foundation.h>
#import <Security/AuthorizationPlugin.h>
#import <Security/AuthorizationTags.h>
#import <os/log.h>

extern void atlas_mfa_run(const char *user, const char *password, int passwordLen, void *ctx, void (*done)(void *ctx, int allow));

typedef struct {
    const AuthorizationCallbacks *callbacks;
} AtlasPlugin;

typedef struct {
    AtlasPlugin *plugin;
    AuthorizationEngineRef engine;
} AtlasMechanism;

static void atlas_done(void *ctx, int allow) {
    AtlasMechanism *m = (AtlasMechanism *)ctx;
    m->plugin->callbacks->SetResult(m->engine, allow ? kAuthorizationResultAllow : kAuthorizationResultDeny);
}

static OSStatus PluginDestroy(AuthorizationPluginRef plugin) {
    free(plugin);
    return noErr;
}

static OSStatus MechanismCreate(AuthorizationPluginRef plugin, AuthorizationEngineRef engine,
                                AuthorizationMechanismId mechanismId, AuthorizationMechanismRef *outMechanism) {
    AtlasMechanism *m = calloc(1, sizeof(AtlasMechanism));
    if (!m) return errAuthorizationInternal;
    m->plugin = (AtlasPlugin *)plugin;
    m->engine = engine;
    *outMechanism = m;
    return noErr;
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef mechanism) {
    AtlasMechanism *m = (AtlasMechanism *)mechanism;
    const AuthorizationCallbacks *cb = m->plugin->callbacks;
    AuthorizationContextFlags flags = 0;
    const AuthorizationValue *value = NULL;
    // builtin:authenticate (earlier in the rule) has already verified the password for this account.
    if (cb->GetContextValue(m->engine, kAuthorizationEnvironmentUsername, &flags, &value) != noErr
        || value == NULL || value->length == 0 || value->length > 255 || value->data == NULL) {
        cb->SetResult(m->engine, kAuthorizationResultDeny);   // fail closed
        return noErr;
    }
    char user[256];
    memcpy(user, value->data, value->length);
    user[value->length] = 0;
    // The password in the context is NOT proof of authentication; Swift verifies it with OpenDirectory before any Atlas call.
    char *pw = NULL; int pwLen = 0;
    const AuthorizationValue *pv = NULL;
    if (cb->GetContextValue(m->engine, kAuthorizationEnvironmentPassword, &flags, &pv) == noErr
        && pv != NULL && pv->data != NULL && pv->length > 0 && pv->length <= 1024) {
        pw = malloc(pv->length + 1);
        if (pw) { memcpy(pw, pv->data, pv->length); pw[pv->length] = 0; pwLen = (int)pv->length; }
    }
    atlas_mfa_run(user, pw, pwLen, m, atlas_done);   // Swift copies what it needs; we wipe ours
    if (pw) { memset_s(pw, pwLen + 1, 0, pwLen + 1); free(pw); }
    memset_s(user, sizeof(user), 0, sizeof(user));
    return noErr;
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef mechanism) {
    AtlasMechanism *m = (AtlasMechanism *)mechanism;
    return m->plugin->callbacks->DidDeactivate(m->engine);
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef mechanism) {
    free(mechanism);
    return noErr;
}

static const AuthorizationPluginInterface kInterface = {
    kAuthorizationPluginInterfaceVersion, PluginDestroy, MechanismCreate, MechanismInvoke, MechanismDeactivate, MechanismDestroy,
};

OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks, AuthorizationPluginRef *outPlugin,
                                   const AuthorizationPluginInterface **outInterface) {
    AtlasPlugin *p = calloc(1, sizeof(AtlasPlugin));
    if (!p) return errAuthorizationInternal;
    p->callbacks = callbacks;
    *outPlugin = p;
    *outInterface = &kInterface;
    return noErr;
}

