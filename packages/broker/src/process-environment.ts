const SAFE_ENVIRONMENT_KEY = /^[A-Z_][A-Z0-9_]{0,63}$/u;
const SECRET_ENVIRONMENT_KEY = /(?:API|AUTH|COOKIE|CREDENTIAL|KEY|PASSWORD|PASSWD|SECRET|TOKEN|AWS|GITHUB|OPENAI|SSH)/iu;
const EXECUTION_CONTROL_ENVIRONMENT_KEY = /^(?:PATH|HOME|SHELL|PWD|OLDPWD|TMP|TEMP|TMPDIR|NODE_OPTIONS|NODE_PATH|DYLD_[A-Z0-9_]*|LD_[A-Z0-9_]*|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PYTHONINSPECT|RUBYOPT|RUBYLIB|PERL5LIB|PERL5OPT|BASH_ENV|ENV|CDPATH|GIT_[A-Z0-9_]*|DOCKER_[A-Z0-9_]*|NPM_CONFIG_[A-Z0-9_]*)$/u;
const FIXED_ADAPTER_ENVIRONMENT_KEY = /^(?:HOME|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_NO_REPLACE_OBJECTS|GIT_NO_LAZY_FETCH|GIT_ALLOW_PROTOCOL|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|DOCKER_CONFIG|DOCKER_HOST)$/u;

/**
 * Process environments are explicit profile data, never inherited ambient
 * state. Execution-control and loader variables remain forbidden even when a
 * caller supplies an allowlist, because they can change command resolution or
 * inject code into an otherwise fixed executable.
 */
export function isSafeProcessEnvironmentKey(value: unknown, allowFixedAdapterKeys = false): value is string {
  return typeof value === "string" && SAFE_ENVIRONMENT_KEY.test(value) &&
    !SECRET_ENVIRONMENT_KEY.test(value) &&
    (!EXECUTION_CONTROL_ENVIRONMENT_KEY.test(value) || (allowFixedAdapterKeys && FIXED_ADAPTER_ENVIRONMENT_KEY.test(value)));
}
