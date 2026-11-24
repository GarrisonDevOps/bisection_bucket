use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;
use std::time::Duration;

use magnus::rb_sys::AsRawValue;
use magnus::{Error, Ruby, prelude::*};
use prost::Message;

/// Thin 1:1 wrapper around `glaz_module::PermissionCheckEngine`. The engine
/// starts empty; `load_schema` must be called before `load_policies`, and
/// `check_action` fails with a RuntimeError until both are loaded.
#[magnus::wrap(class = "Glaz::PermissionCheckEngine")]
struct PermissionCheckEngine {
    engine: glaz_module::PermissionCheckEngine,
}

impl PermissionCheckEngine {
    fn initialize(ruby: &Ruby) -> Result<Self, Error> {
        let engine = glaz_module::PermissionCheckEngine::new().map_err(|e| map_error(ruby, e))?;

        Ok(Self { engine })
    }

    /// Load the Cedar schema. Re-loading a schema drops the active policies,
    /// so callers should load the schema exactly once, before any policies.
    fn load_schema(ruby: &Ruby, rb_self: &Self, schema: String) -> Result<(), Error> {
        rb_self
            .engine
            .load_schema(&schema)
            .map_err(|e| map_error(ruby, e))
    }

    /// Replace the active policy set with the given Cedar policy source,
    /// validated against the loaded schema. On error the previous policies
    /// remain active.
    fn load_policies(ruby: &Ruby, rb_self: &Self, policies: String) -> Result<(), Error> {
        rb_self
            .engine
            .load_policies(&policies)
            .map_err(|e| map_error(ruby, e))
    }

    fn check_action(
        ruby: &Ruby,
        rb_self: &Self,
        proto_bytes: magnus::RString,
    ) -> Result<magnus::RHash, Error> {
        let bytes = unsafe { proto_bytes.as_slice() };
        let result = rb_self
            .engine
            .check(bytes)
            .map_err(|e| map_error(ruby, e))?;
        let hash = ruby.hash_new();
        hash.aset(ruby.sym_new("allowed"), result.allowed)?;
        hash.aset(ruby.sym_new("reason"), result.reason)?;
        Ok(hash)
    }
}

/// Thin 1:1 wrapper around `glaz_module::GovernPolicyCheckEngine`, the Rego
/// governance evaluator. A request may carry its own policies
/// (`EvaluateGovernPolicyRequest.policies`); then no lookup runs. Otherwise
/// the lookup fetches from the Policy Store REST API named at construction,
/// authenticated per request on
/// `EvaluateGovernPolicyRequest.store_authorization`. Stateless between
/// calls. `evaluate_policies` raises on a whole-call failure (matching
/// `PermissionCheckEngine`'s convention): `ArgumentError` for caller
/// faults, `RuntimeError` for backend faults, see `map_error`.
/// `debug_evaluate` and `validate` are infallible for policy errors, which
/// they return in-band; only a malformed protobuf payload raises.
///
/// Registered as `Glaz::Native::GovernPolicyEngine` to avoid colliding in
/// name with the `Gitlab::Glaz::GovernPolicyEngine` wrapper — this class is
/// raw FFI plumbing; prefer the wrapper.
#[magnus::wrap(class = "Glaz::Native::GovernPolicyEngine")]
struct GovernPolicyEngine {
    // Shared with the per-call lookup thread, see `on_own_thread`.
    engine: Arc<glaz_module::GovernPolicyCheckEngine>,
}

impl GovernPolicyEngine {
    /// `base_url` is the Policy Store REST API root (e.g.
    /// `"https://gitlab.com/api/v4"`); `nil` timeouts keep
    /// `glaz-govern`'s defaults. Without `base_url` the engine has no policy
    /// lookup: `validate` and `debug_evaluate` work, and `evaluate_policies`
    /// works for a request that carries its own policies. Any other
    /// `evaluate_policies` call fails closed (see `NoStore`).
    fn initialize(
        base_url: Option<String>,
        connect_timeout_ms: Option<u64>,
        timeout_ms: Option<u64>,
    ) -> Self {
        let Some(base_url) = base_url else {
            return Self {
                engine: Arc::new(glaz_module::GovernPolicyCheckEngine::with_lookup(NoStore)),
            };
        };
        let mut config = glaz_module::StoreConfig::new(base_url);
        if let Some(ms) = connect_timeout_ms {
            config = config.with_connect_timeout(Duration::from_millis(ms));
        }
        if let Some(ms) = timeout_ms {
            config = config.with_total_timeout(Duration::from_millis(ms));
        }
        Self {
            engine: Arc::new(glaz_module::GovernPolicyCheckEngine::with_store(config)),
        }
    }

    /// Evaluate the request's `query` directly, with no
    /// `violation`/`deny`/`allow` interpretation and no policy lookup. A
    /// blank query is reported in-band.
    ///
    /// Runs with the GVL released (`without_gvl`), on its own thread where a
    /// forked child needs one (`on_own_thread`): the parse it performs
    /// parks the calling thread the same way `evaluate_policies`'s lookup
    /// does. Not interruptible from Ruby until it returns.
    fn debug_evaluate(
        ruby: &Ruby,
        rb_self: &Self,
        proto_bytes: magnus::RString,
    ) -> Result<magnus::RString, Error> {
        // Copy the request out of the Ruby string first: once the GVL is
        // released the GC may move or free the buffer behind `as_slice`.
        let request = unsafe { proto_bytes.as_slice() }.to_vec();
        let engine = Arc::clone(&rb_self.engine);
        let response = without_gvl(ruby, move || {
            on_own_thread(move || Ok(engine.debug_evaluate(&request)))
        })?
        .map_err(|e| map_error(ruby, e))?;
        Ok(ruby.str_from_slice(&response))
    }

    /// Trigger-keyed batch evaluation: takes an encoded
    /// `EvaluateGovernPolicyRequest`, takes the policies from the request's
    /// `policies` when set and from the Policy Store otherwise (keyed on
    /// `trigger` and the context's `organization.id`), and returns the
    /// encoded `EvaluateGovernPolicyResponse`. Raises `ArgumentError` for caller
    /// faults and `RuntimeError` for backend faults — never an empty batch,
    /// which would read fail-open. A broken individual policy is reported
    /// in-band on its decision's `error`.
    ///
    /// Runs with the GVL released (`without_gvl`), on its own thread where
    /// a forked child needs one (`on_own_thread`). Not interruptible from
    /// Ruby until it returns.
    fn evaluate_policies(
        ruby: &Ruby,
        rb_self: &Self,
        proto_bytes: magnus::RString,
    ) -> Result<magnus::RString, Error> {
        // Copy the request out of the Ruby string first: once the GVL is
        // released the GC may move or free the buffer behind `as_slice`.
        let request = unsafe { proto_bytes.as_slice() }.to_vec();
        let engine = Arc::clone(&rb_self.engine);
        let response = without_gvl(ruby, move || {
            on_own_thread(move || {
                engine
                    .evaluate_policies(&request)
                    .map(|response| response.encode_to_vec())
            })
        })?
        .map_err(|e| map_error(ruby, e))?;
        Ok(ruby.str_from_slice(&response))
    }

    /// Dry-run twin of `evaluate_policies` (GOVERN-004: a method of its own,
    /// never a flag). Takes an encoded `EvaluateGovernPolicyRequest` with
    /// `dry_run` set and returns the encoded response echoing it; same
    /// errors, GVL release and thread handling as `evaluate_policies`.
    fn evaluate_policies_dry_run(
        ruby: &Ruby,
        rb_self: &Self,
        proto_bytes: magnus::RString,
    ) -> Result<magnus::RString, Error> {
        // Copy the request out of the Ruby string first: once the GVL is
        // released the GC may move or free the buffer behind `as_slice`.
        let request = unsafe { proto_bytes.as_slice() }.to_vec();
        let engine = Arc::clone(&rb_self.engine);
        let response = without_gvl(ruby, move || {
            on_own_thread(move || {
                engine
                    .evaluate_policies_dry_run(&request)
                    .map(|response| response.encode_to_vec())
            })
        })?
        .map_err(|e| map_error(ruby, e))?;
        Ok(ruby.str_from_slice(&response))
    }

    /// List an encoded `ListGovernPoliciesRequest`: every policy the lookup
    /// resolves for the trigger and scope, each with whether it applies to
    /// the context supplied. Evaluates no policy's rules, so the encoded
    /// `ListGovernPoliciesResponse` carries nothing to gate on. Same errors,
    /// GVL release and thread handling as `evaluate_policies`; a policy whose
    /// scope fails to evaluate comes back in-band on its own row.
    fn list_policies(
        ruby: &Ruby,
        rb_self: &Self,
        proto_bytes: magnus::RString,
    ) -> Result<magnus::RString, Error> {
        // Copy the request out of the Ruby string first: once the GVL is
        // released the GC may move or free the buffer behind `as_slice`.
        let request = unsafe { proto_bytes.as_slice() }.to_vec();
        let engine = Arc::clone(&rb_self.engine);
        let response = without_gvl(ruby, move || {
            on_own_thread(move || {
                engine
                    .list_policies(&request)
                    .map(|response| response.encode_to_vec())
            })
        })?
        .map_err(|e| map_error(ruby, e))?;
        Ok(ruby.str_from_slice(&response))
    }

    /// Parse and compile a Rego policy without evaluating it against input.
    ///
    /// Infallible for policy errors: parse failures and oversized input are
    /// returned in-band as `{ valid: false, errors: [...] }` rather than
    /// raised. Only a malformed protobuf payload raises `ArgumentError`; an
    /// internal engine fault raises `RuntimeError` via `map_error`.
    ///
    /// Runs with the GVL released (`without_gvl`), on its own thread where a
    /// forked child needs one (`on_own_thread`): the parse it performs
    /// parks the calling thread the same way `evaluate_policies`'s lookup
    /// does. Not interruptible from Ruby until it returns.
    fn validate(
        ruby: &Ruby,
        rb_self: &Self,
        proto_bytes: magnus::RString,
    ) -> Result<magnus::RString, Error> {
        // Copy the request out of the Ruby string first: once the GVL is
        // released the GC may move or free the buffer behind `as_slice`.
        let request = unsafe { proto_bytes.as_slice() }.to_vec();
        let engine = Arc::clone(&rb_self.engine);
        let response = without_gvl(ruby, move || {
            on_own_thread(move || {
                engine
                    .validate(&request)
                    .map(|response| response.encode_to_vec())
            })
        })?
        .map_err(|e| map_error(ruby, e))?;
        Ok(ruby.str_from_slice(&response))
    }
}

/// The lookup of an engine constructed without a Policy Store: every
/// lookup fails closed as `LookupError::Unavailable` (a `RuntimeError`), so
/// such an engine can never report "nothing to enforce" for a request
/// without its own policies. The Ruby wrapper rejects that call earlier
/// with configuration guidance.
struct NoStore;

impl glaz_module::PolicyLookup for NoStore {
    fn lookup(
        &self,
        _key: &glaz_module::LookupKey,
        _store_authorization: &str,
    ) -> Result<Vec<glaz_module::StoredPolicy>, glaz_module::LookupError> {
        Err(glaz_module::LookupError::Unavailable(
            "no Policy Store configured for this engine".to_string(),
        ))
    }
}

/// Return the default roles embedded in the extension at build time (parsed
/// from glaz-roles' roles/**/*.yml) as an array of hashes shaped like
/// `{ id: String, key: String, name: String, permissions: [String, ...] }`.
///
/// `key` is the role's stable machine identifier (e.g. `artifact_admin`),
/// distinct from the human-facing `name` and from the `id` callers put in
/// relationships. Callers reference a role by `key` instead of hardcoding
/// its UUID or matching on its display name.
fn roles(ruby: &Ruby) -> Result<magnus::RArray, Error> {
    let array = ruby.ary_new();
    for role in glaz_roles::default_roles() {
        let hash = ruby.hash_new();
        hash.aset(ruby.sym_new("id"), role.id.to_string())?;
        hash.aset(ruby.sym_new("key"), role.key)?;
        hash.aset(ruby.sym_new("name"), role.name)?;
        let permissions = ruby.ary_new();
        for permission in &role.permissions {
            permissions.push(permission.as_str())?;
        }
        hash.aset(ruby.sym_new("permissions"), permissions)?;
        array.push(hash)?;
    }
    Ok(array)
}

/// Run `func` with the GVL released and hand its result back once the GVL
/// is held again. `func` must not touch the Ruby VM, so callers copy their
/// input out of Ruby objects first. A panic in `func` is caught at the
/// `extern "C"` boundary and resumed afterwards.
///
/// No unblock function is registered, so `func` always runs to completion;
/// a Ruby interrupt aimed at this thread takes effect once it returns.
///
/// Catching the panic requires `panic = "unwind"`, the default profile
/// setting; magnus's method wrappers already rely on it to turn panics into
/// Ruby exceptions, so an `abort` profile would break the extension as a
/// whole, not just this helper.
fn without_gvl<F, T>(ruby: &Ruby, func: F) -> Result<T, Error>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    enum Call<F, T> {
        Pending(F),
        Done(std::thread::Result<T>),
    }

    unsafe extern "C" fn trampoline<F: FnOnce() -> T, T>(data: *mut c_void) -> *mut c_void {
        // SAFETY: `data` is the `Call` below, which outlives this call.
        let slot = unsafe { &mut *data.cast::<Option<Call<F, T>>>() };
        let Some(Call::Pending(func)) = slot.take() else {
            unreachable!("the trampoline runs exactly once, on a pending call");
        };
        *slot = Some(Call::Done(catch_unwind(AssertUnwindSafe(func))));
        std::ptr::null_mut()
    }

    let mut call = Some(Call::Pending(func));
    // `protect` catches Ruby unwinding out of the interrupt checks
    // `rb_thread_call_without_gvl` performs before and after `func`.
    let protected = magnus::rb_sys::protect(|| {
        unsafe {
            rb_sys::rb_thread_call_without_gvl(
                Some(trampoline::<F, T>),
                (&mut call as *mut Option<Call<F, T>>).cast::<c_void>(),
                None,
                std::ptr::null_mut(),
            );
        }
        ruby.qnil().as_raw()
    });

    // A panic outranks an interrupt that arrived after it.
    match call {
        Some(Call::Done(Err(panic))) => resume_unwind(panic),
        Some(Call::Done(Ok(value))) => protected.map(|_| value),
        Some(Call::Pending(_)) | None => {
            protected?;
            unreachable!("rb_thread_call_without_gvl returned without running the call")
        }
    }
}

/// On Apple targets, run `func` on a native thread of its own; elsewhere,
/// inline.
///
/// While resolving a host name under a timeout the HTTP client parks its
/// thread, and on Apple targets Rust's `std` parks with a per-thread
/// libdispatch semaphore. A forked child inherits the forking thread's
/// semaphore and libdispatch aborts the process (`SIGTRAP`) on its first
/// use, so a Unicorn worker evaluating on the thread its master evaluated
/// on would crash. A fresh thread gets a fresh semaphore. Linux parks on a
/// futex, which survives a fork.
fn on_own_thread<F, T>(func: F) -> Result<T, glaz_module::GlazError>
where
    F: FnOnce() -> Result<T, glaz_module::GlazError> + Send + 'static,
    T: Send + 'static,
{
    #[cfg(not(target_vendor = "apple"))]
    {
        func()
    }
    #[cfg(target_vendor = "apple")]
    {
        let handle = std::thread::Builder::new()
            .name("glaz-policy-lookup".to_string())
            // The main thread's 8 MiB rather than the 2 MiB spawn default.
            .stack_size(8 << 20)
            .spawn(func)
            .map_err(|e| {
                glaz_module::GlazError::Runtime(format!(
                    "could not start the policy lookup thread: {e}"
                ))
            })?;
        match handle.join() {
            Ok(result) => result,
            Err(panic) => resume_unwind(panic),
        }
    }
}

// The engine is called concurrently from any thread: other Ruby threads
// while one waits outside the GVL, and the lookup thread on Apple targets.
const _: () = {
    const fn assert_sync_send<T: Sync + Send>() {}
    assert_sync_send::<glaz_module::GovernPolicyCheckEngine>();
};

fn map_error(ruby: &Ruby, e: glaz_module::GlazError) -> Error {
    use glaz_module::GlazError::*;
    match e {
        InvalidArgument(_) => Error::new(ruby.exception_arg_error(), format!("{e}")),
        NotInitialized(_) => Error::new(ruby.exception_runtime_error(), format!("{e}")),
        Runtime(_) => Error::new(ruby.exception_runtime_error(), format!("{e}")),
    }
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let glaz = ruby.define_module("Glaz")?;
    glaz.define_singleton_method("roles", magnus::function!(roles, 0))?;
    let class = glaz.define_class("PermissionCheckEngine", ruby.class_object())?;
    class.define_singleton_method(
        "new",
        magnus::function!(PermissionCheckEngine::initialize, 0),
    )?;
    class.define_method(
        "load_schema",
        magnus::method!(PermissionCheckEngine::load_schema, 1),
    )?;
    class.define_method(
        "load_policies",
        magnus::method!(PermissionCheckEngine::load_policies, 1),
    )?;
    class.define_method(
        "check_action",
        magnus::method!(PermissionCheckEngine::check_action, 1),
    )?;
    let native = glaz.define_module("Native")?;
    let govern = native.define_class("GovernPolicyEngine", ruby.class_object())?;
    govern.define_singleton_method("new", magnus::function!(GovernPolicyEngine::initialize, 3))?;
    govern.define_method(
        "debug_evaluate",
        magnus::method!(GovernPolicyEngine::debug_evaluate, 1),
    )?;
    govern.define_method(
        "evaluate_policies",
        magnus::method!(GovernPolicyEngine::evaluate_policies, 1),
    )?;
    govern.define_method(
        "evaluate_policies_dry_run",
        magnus::method!(GovernPolicyEngine::evaluate_policies_dry_run, 1),
    )?;
    govern.define_method(
        "list_policies",
        magnus::method!(GovernPolicyEngine::list_policies, 1),
    )?;
    govern.define_method("validate", magnus::method!(GovernPolicyEngine::validate, 1))?;
    Ok(())
}
