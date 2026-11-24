# frozen_string_literal: true

require "json"
require "uri"

module Gitlab
  module Glaz
    # Wraps a native Glaz::Native::GovernPolicyEngine - the Rego governance
    # policy evaluator.
    #
    # Evaluation is trigger-keyed: the caller supplies an event trigger and
    # the context document. The policies come either with the call
    # (+policies:+ on #evaluate, for a caller that already has them, such as
    # the Policy Store itself) or from the Policy Store REST API named at
    # construction. Authentication for the REST API is per request
    # (+store_authorization+ on #evaluate), never per engine and never from
    # the environment. The engine executes no actions; the caller does.
    #
    # #validate and #debug_evaluate never touch the store, so an engine
    # built without one still serves them, and serves #evaluate when
    # +policies:+ is given. An #evaluate call without +policies:+ on such an
    # engine fails closed with an ArgumentError.
    #
    # #evaluate releases the GVL around the native call. It cannot be
    # interrupted from Ruby until it returns, which is bounded by the lookup
    # timeouts plus the batch evaluation. Instances are safe to share across
    # threads and across a fork.
    class GovernPolicyEngine
      # Argument checks, raising ArgumentError instead of letting a
      # Google::Protobuf::TypeError or JSON error escape from the wire layer.
      #
      # @api private
      module Validation
        module_function

        INVALID_STORE_BASE_URL_MESSAGE = "store_base_url must be an http(s) URL naming the Policy Store REST API " \
          "root (e.g. \"https://gitlab.com/api/v4\"), without credentials, query or fragment, and with a port " \
          "in 1..65535"
        private_constant :INVALID_STORE_BASE_URL_MESSAGE

        def store_base_url!(url)
          string!(url, "store_base_url")

          parsed = begin
            URI.parse(url)
          rescue URI::Error
            nil
          end
          raise ArgumentError, INVALID_STORE_BASE_URL_MESSAGE unless valid_store_base_url?(parsed)

          -url
        end

        def string!(value, name)
          raise ArgumentError, "#{name} must be a String; got #{value.class}" unless value.is_a?(String)

          value
        end

        # The message never echoes +value+: it is a credential.
        def store_authorization!(value)
          return value.to_s if value.nil? || value.is_a?(String)

          raise ArgumentError, "store_authorization must be nil or a String; got a #{value.class}"
        end

        # The native side takes a u64 of milliseconds.
        def timeout!(value, name)
          return value if value.nil? || (value.is_a?(Integer) && value.positive? && value.bit_length <= 64)

          raise ArgumentError, "#{name} must be nil or a positive Integer of at most 64 bits; got #{value.inspect}"
        end

        def json!(document, name)
          raise ArgumentError, "#{name} must be a Hash; got #{document.class}" unless document.is_a?(Hash)

          JSON.generate(document)
        rescue JSON::JSONError => e
          raise ArgumentError, "#{name} must serialize to JSON; #{e.message}"
        end

        def presence(string)
          string.nil? || string.empty? ? nil : string
        end

        MODES = {
          "enforce" => :GOVERN_ENFORCEMENT_MODE_ENFORCE,
          "audit" => :GOVERN_ENFORCEMENT_MODE_AUDIT,
          "warn" => :GOVERN_ENFORCEMENT_MODE_WARN
        }.freeze
        private_constant :MODES

        # Builds the wire set from policy Hashes shaped like the Policy
        # Store's policy entity. String or Symbol keys; keys the engine does
        # not read, such as +lifecycle_state+, are ignored. Only the shape is
        # checked here. Whether each policy belongs to the request's trigger
        # and organization is the engine's check.
        def policies!(policies)
          return nil if policies.nil?
          raise ArgumentError, "policies must be nil or an Array; got #{policies.class}" unless policies.is_a?(Array)

          ::Gitlab::Glaz::Govern::V1::GovernPolicySet.new(
            policies: policies.each_with_index.map { |policy, index| policy!(policy, "policies[#{index}]") }
          )
        end

        def policy!(policy, name)
          raise ArgumentError, "#{name} must be a Hash; got #{policy.class}" unless policy.is_a?(Hash)

          policy = policy.transform_keys(&:to_s)
          # Name the policy by id as well, as the native layer's errors do.
          name = "#{name} (id #{policy['id']})" if policy["id"].is_a?(Integer)
          dimensions, namespace_id = policy.values_at("scope_dimensions", "namespace_id")

          attributes = {
            id: integer!(policy["id"], "#{name}.id"),
            name: optional_string!(policy["name"], "#{name}.name"),
            trigger: string!(policy["trigger_type"], "#{name}.trigger_type"),
            organization_id: integer!(policy["organization_id"], "#{name}.organization_id"),
            mode: mode!(policy["mode"], "#{name}.mode"),
            scope_rego: optional_string!(policy["scope_rego"], "#{name}.scope_rego"),
            scope_dimensions: dimensions.nil? ? nil : scope_dimensions!(dimensions, "#{name}.scope_dimensions"),
            policy_rego: string!(policy["policy_rego"], "#{name}.policy_rego"),
            actions: actions!(policy["actions"], "#{name}.actions"),
            violation_details: violation_details!(policy["violation_details"], "#{name}.violation_details")
          }
          # The owner is explicit on the wire: nil is an organization-level
          # policy, never an unset field, so a missing key is an error rather
          # than a silent default.
          unless policy.key?("namespace_id")
            raise ArgumentError, "#{name}.namespace_id must be present (nil for an organization-level policy)"
          end

          if namespace_id.nil?
            attributes[:organization_level] = true
          else
            attributes[:namespace_id] = integer!(namespace_id, "#{name}.namespace_id")
          end

          ::Gitlab::Glaz::Govern::V1::GovernPolicy.new(attributes)
        end

        def integer!(value, name)
          unless value.is_a?(Integer) && !value.negative? && value.bit_length <= 64
            raise ArgumentError, "#{name} must be a non-negative Integer of at most 64 bits; got #{value.inspect}"
          end

          value
        end

        def optional_string!(value, name)
          value.nil? ? "" : string!(value, name)
        end

        def mode!(value, name)
          MODES.fetch(value.to_s) do
            raise ArgumentError, "#{name} must be one of #{MODES.keys.join(', ')}; got #{value.inspect}"
          end
        end

        # The engine stamps a mode on every decision, so an unspecified or
        # unknown one is an engine fault, not a caller mistake.
        def mode_name(value)
          MODES.key(value) || raise("decision carries no enforcement mode; got #{value.inspect}")
        end

        def scope_dimensions!(value, name)
          unless value.is_a?(Array) && value.all?(String)
            raise ArgumentError, "#{name} must be nil or an Array of Strings; got #{value.inspect}"
          end

          ::Gitlab::Glaz::Govern::V1::GovernScopeDimensions.new(paths: value)
        end

        # The store entity's saved constraints, forwarded onto the policy's
        # decision as the store lookup forwards them: nil means none, a nil
        # or missing +expected+ names no value, and other keys are ignored.
        # The engine checks each path's segments.
        def violation_details!(value, name)
          return [] if value.nil?
          raise ArgumentError, "#{name} must be nil or an Array; got #{value.class}" unless value.is_a?(Array)

          value.each_with_index.map { |detail, index| violation_detail!(detail, "#{name}[#{index}]") }
        end

        def violation_detail!(detail, name)
          raise ArgumentError, "#{name} must be a Hash; got #{detail.class}" unless detail.is_a?(Hash)

          detail = detail.transform_keys(&:to_s)
          expected = detail["expected"]
          ::Gitlab::Glaz::Govern::V1::GovernViolationDetail.new(
            path: string!(detail["path"], "#{name}.path"),
            expected_json: expected.nil? ? "" : JSON.generate(expected)
          )
        rescue JSON::JSONError => e
          raise ArgumentError, "#{name}.expected must serialize to JSON; #{e.message}"
        end

        def actions!(value, name)
          return [] if value.nil?
          raise ArgumentError, "#{name} must be nil or an Array; got #{value.class}" unless value.is_a?(Array)

          value.each_with_index.map { |action, index| action!(action, "#{name}[#{index}]") }
        end

        def action!(action, name)
          raise ArgumentError, "#{name} must be a Hash; got #{action.class}" unless action.is_a?(Hash)

          action = action.transform_keys(&:to_s)
          value = action["value"]

          ::Gitlab::Glaz::Govern::V1::GovernPolicyAction.new(
            action_type: string!(action["type"], "#{name}.type"),
            value_json: value.nil? ? "" : json!(value, "#{name}.value")
          )
        end

        def valid_store_base_url?(parsed_uri)
          parsed_uri.is_a?(URI::HTTP) && !parsed_uri.host.to_s.empty? &&
            parsed_uri.userinfo.nil? && parsed_uri.query.nil? && parsed_uri.fragment.nil? &&
            parsed_uri.port.between?(1, 65_535)
        end
      end
      private_constant :Validation

      # Serializes .shared against .policy_store_url=: without it, a .shared
      # call that read the old URL could finish after a reconfiguration and
      # leave an engine for the old store memoized.
      CONFIGURATION_LOCK = Mutex.new
      private_constant :CONFIGURATION_LOCK

      class << self
        # @return [GovernPolicyEngine] a process-wide engine for
        #   +.policy_store_url+, built on first access and memoized until
        #   +.policy_store_url=+ next reconfigures it.
        # @raise [ArgumentError] if +GLAZ_POLICY_STORE_URL+ is set but is not
        #   a valid Policy Store REST API root.
        def shared
          CONFIGURATION_LOCK.synchronize { @shared ||= new(store_base_url: policy_store_url) }
        end

        # @return [String, nil] the Policy Store REST API root the next
        #   +.shared+ call builds its engine with: an explicitly assigned URL
        #   (see +.policy_store_url=+) takes precedence, otherwise
        #   +GLAZ_POLICY_STORE_URL+; a blank value counts as unset (+nil+).
        def policy_store_url
          @policy_store_url || Validation.presence(ENV["GLAZ_POLICY_STORE_URL"]&.strip)
        end

        # Point the shared engine at a Policy Store REST API root; the next
        # .shared call rebuilds it. +nil+ falls back to the environment variable.
        #
        # @raise [ArgumentError] when +url+ is neither nil nor an http(s) URL
        #   without credentials, query or fragment.
        def policy_store_url=(url)
          validated = url.nil? ? nil : Validation.store_base_url!(url)
          CONFIGURATION_LOCK.synchronize do
            @policy_store_url = validated
            @shared = nil
          end
        end
      end

      # @return [String, nil] the Policy Store REST API root; nil for an
      #   engine with no store.
      attr_reader :store_base_url

      # @param store_base_url [String, nil] the Policy Store REST API root,
      #   e.g. `"https://gitlab.com/api/v4"`; the lookup performs
      #   `GET {store_base_url}/organizations/{id}/security/policy_store?trigger_type={trigger}`.
      #   Redirects are never followed; `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY`
      #   and `NO_PROXY` apply. +nil+ builds an engine with no store.
      # @param connect_timeout_ms [Integer, nil] lookup connect timeout
      #   (default 500 ms).
      # @param timeout_ms [Integer, nil] lookup total timeout (default 2 s).
      # @raise [ArgumentError] for an invalid URL, or a timeout that is
      #   neither nil nor a positive 64-bit Integer.
      def initialize(store_base_url: nil, connect_timeout_ms: nil, timeout_ms: nil)
        @store_base_url = store_base_url.nil? ? nil : Validation.store_base_url!(store_base_url)
        @connect_timeout_ms = Validation.timeout!(connect_timeout_ms, "connect_timeout_ms")
        @timeout_ms = Validation.timeout!(timeout_ms, "timeout_ms")
        @pid = Process.pid
        @rebuild_lock = Mutex.new
        @native = build_native
      end

      # Evaluate every governance policy that applies to an event trigger.
      # +context+ must carry the evaluation scope at `organization.id` as a
      # resource path (e.g. `"organizations/1"`).
      #
      # @param trigger [String] the event, e.g. "deployment_requested".
      # @param context [Hash] the Rego `input` document for every policy in
      #   the batch (max 1 MiB as JSON).
      # @param principal [String] who the decision is about, as an opaque
      #   path-style identifier string (e.g. `"users/42"`); the caller owns
      #   the naming scheme. Trimmed of surrounding whitespace; must not be
      #   blank, contain a newline, or exceed 64 KiB once trimmed.
      # @param resource [String] what the decision is about, as an opaque
      #   path-style identifier string (e.g.
      #   `"organizations/1/deployments/9"`). Same validation as
      #   +principal+.
      # @param data [Hash, nil] optional Rego `data` document shared by the
      #   batch. It must not define a policy's own decision rules
      #   (`violation`/`deny`/`allow`); the engine reports that on the
      #   policy's +error+.
      # @param store_authorization [String, nil] the `Authorization` header
      #   value the lookup presents to the Policy Store, verbatim (target
      #   scheme `"Bearer <jwt>"`). nil sends no header. Never logged or
      #   echoed in errors. Ignored when +policies+ is given.
      # @param policies [Array<Hash>, nil] the policies to evaluate, for a
      #   caller that already has them. When given, the engine evaluates
      #   exactly these and never contacts the store; an empty Array is a
      #   successful, empty evaluation. nil fetches them from the store.
      #   Pass the active policies of +trigger+ in the context's
      #   organization, each shaped like the Policy Store's policy entity
      #   (String or Symbol keys): `id`, `name`, `trigger_type`,
      #   `organization_id`, `namespace_id` (required; nil for an
      #   organization-level policy), `mode` (`"enforce"`, `"audit"` or
      #   `"warn"`), `scope_rego` (nil or empty when unscoped),
      #   `scope_dimensions` (Array<String>, or nil when unknown),
      #   `policy_rego`, `actions` (`{ type:, value: }` entries) and
      #   `violation_details` (nil, or `{ path:, expected: }` entries: the
      #   constraints the store saved from {#validate}, forwarded onto the
      #   policy's decision; `path` is a String and `expected`, nil when the
      #   policy names no compliant value, must serialize to JSON). Other
      #   keys are ignored.
      # @raise [ArgumentError] for a caller fault: wrong argument types, a
      #   document that does not serialize to JSON, a blank trigger, a blank
      #   +principal+ or +resource+ (or one exceeding 64 KiB or carrying a
      #   newline), missing organization scope, an oversized input document,
      #   a policy in +policies+ that is malformed or belongs to another
      #   trigger, organization or namespace, more than the per-trigger cap
      #   of them, or an engine without a store called without +policies+.
      # @raise [RuntimeError] for a backend fault: the store lookup failed
      #   or was rejected, or resolved more policies than the per-trigger
      #   cap. Never an empty batch, which would read as "nothing to
      #   enforce". Also when the engine stamps the response dry_run.
      # @return [Hash] `{ decisions: Array<Hash>, undecided_policy_ids:
      #   Array<Integer>, identifier: String,
      #   dry_run: Boolean }`. +decisions+ has one entry
      #   per resolved, in-scope policy, in lookup order; empty means
      #   nothing applies. Each decision is `{ policy_id: Integer, matched:
      #   Boolean, actions: Array<Hash>, reasons: Array<Hash>, error: String
      #   | nil, name: String, mode: String, violation_details: Array<Hash> }`; each violation
      #   detail is `{ path: String, expected: Object }`, with +expected+ absent when the
      #   policy names no compliant value; each
      #   action `{ action_type: String, message: String | nil, params: Hash, gating: Boolean }`; each
      #   reason `{ message: String | nil, details: Hash }`. +actions+ are exactly those the
      #   store configured on the policy, emitted when it matched. A non-nil
      #   +error+ means the policy could not be decided (broken, or over the
      #   per-evaluation time budget); +matched+ is then false and its id is
      #   listed in +undecided_policy_ids+. +identifier+ is the stable
      #   decision identifier derived from (+principal+, +trigger+,
      #   +resource+): the same subject always yields the same identifier,
      #   so callers can key journaling, action deduplication, and approval
      #   correlation on it.
      #
      #   Verdict: deny when any action is gating or any policy is
      #   undecided, allow otherwise. +matched+ alone decides nothing.
      #   +dry_run+ is always false here; see #evaluate_dry_run to preview.
      def evaluate(trigger:, context:, principal:, resource:, data: nil, store_authorization: nil, policies: nil)
        request = evaluation_request(
          trigger, context, principal, resource, data, store_authorization, policies, dry_run: false
        )

        response = ::Gitlab::Glaz::Govern::V1::EvaluateGovernPolicyResponse.decode(native.evaluate_policies(request))
        # A dry-run stamp on an enforcement response would let a host skip
        # recording a real decision, so treat it as an engine fault.
        raise "enforcement evaluation response is stamped dry_run" if response.dry_run

        evaluation_result(response)
      end

      # Preview what #evaluate would decide, without enforcing it. A method
      # of its own, never a parameter of #evaluate (GOVERN-004): a dry run is
      # never a gate, so callers must not deny on its result, and nothing
      # records it. Takes the same arguments, raises the same errors and
      # returns the same Hash as #evaluate, with +dry_run+ true.
      #
      # @raise [RuntimeError] additionally, when the response does not echo
      #   the dry-run flag, so a dry run can never be mistaken for a verdict.
      # @return [Hash] see #evaluate.
      def evaluate_dry_run(
        trigger:, context:, principal:, resource:, data: nil, store_authorization: nil,
        policies: nil)
        request = evaluation_request(
          trigger, context, principal, resource, data, store_authorization, policies, dry_run: true
        )

        result = evaluation_result(
          ::Gitlab::Glaz::Govern::V1::EvaluateGovernPolicyResponse.decode(native.evaluate_policies_dry_run(request))
        )
        raise "dry-run evaluation response did not echo dry_run" unless result[:dry_run]

        result
      end

      # List every policy that could apply to +trigger+ in the context's
      # organization, each with whether it applies to the context supplied.
      # A different question from #evaluate ("what must I enforce"): it needs
      # only the trigger and the lookup keys (`organization.id`, plus the
      # namespace ids where the trigger needs them), runs no policy's rules
      # and returns no decisions, so nothing in it can be gated on.
      #
      # A policy whose scope reads a context path the caller did not supply
      # is never evaluated, because a missing path would read as "does not
      # apply". It comes back as `"might_apply"` with those paths in
      # +missing_dimensions+: supply them and call again. An explicit nil in
      # the context counts as absent; an empty Array is a value.
      #
      # @param trigger [String] the event, e.g. "deployment_requested".
      # @param context [Hash] whatever context the caller has (max 1 MiB as
      #   JSON). Must carry `organization.id`, plus the namespace ids for a
      #   trigger whose policies belong to namespaces, as on #evaluate.
      # @param store_authorization [String, nil] as on #evaluate.
      # @param policies [Array<Hash>, nil] as on #evaluate.
      # @raise [ArgumentError] for a caller fault, as on #evaluate (there is no
      #   +principal+ or +resource+ to check).
      # @raise [RuntimeError] for a backend fault, as on #evaluate, or a row
      #   whose applicability the engine left unstated without saying why.
      # @return [Hash] `{ policies: Array<Hash> }`, one entry per resolved
      #   policy in lookup order, each `{ policy_id: Integer, name: String,
      #   applicability: "applies" | "not_applicable" | "might_apply" | nil,
      #   missing_dimensions: Array<String>, error: String | nil }`.
      #   +missing_dimensions+ is set only with `"might_apply"`, and may be
      #   empty when the policy's scope paths are unknown. +applicability+
      #   is nil only alongside an +error+: the policy's scope could not be
      #   evaluated, so it is neither included nor ruled out. +name+ is for
      #   display; key on +policy_id+.
      def list_policies(trigger:, context:, store_authorization: nil, policies: nil)
        require_policy_source!(policies)

        encoded = ::Gitlab::Glaz::Govern::V1::ListGovernPoliciesRequest.encode(
          ::Gitlab::Glaz::Govern::V1::ListGovernPoliciesRequest.new(
            trigger: Validation.string!(trigger, "trigger"),
            input_json: Validation.json!(context, "context"),
            store_authorization: Validation.store_authorization!(store_authorization),
            policies: Validation.policies!(policies)
          )
        )
        response = ::Gitlab::Glaz::Govern::V1::ListGovernPoliciesResponse.decode(native.list_policies(encoded))

        { policies: response.policies.map { |row| applicability_hash(row) } }
      end

      # Parse and compile a Rego policy without evaluating it. A policy that
      # fails to parse is not an error: it comes back as
      # `{ valid: false, errors: [...] }` so the Policy Store can surface
      # actionable feedback.
      #
      # @param policy_rego [String] Rego source (max 64 KiB).
      # @param trigger [String, nil] the trigger the policy is authored for. When
      #   given and the engine embeds a schema for it, every extracted detail's
      #   path and expected value are checked against that schema.
      # @raise [ArgumentError] when +policy_rego+ or a given +trigger+ is not a String.
      # @return [Hash] `{ valid: Boolean, errors: Array<Hash>,
      #   violation_details: Array<Hash> }`; each error is `{ message:
      #   String, location: String }` with +location+ in `"LINE:COL"`
      #   format, or `""` when none is available. +violation_details+ has
      #   the shape described on #evaluate and is empty for an invalid
      #   policy.
      def validate(policy_rego:, trigger: nil)
        encoded = ::Gitlab::Glaz::Govern::V1::ValidateGovernPolicyRequest.encode(
          ::Gitlab::Glaz::Govern::V1::ValidateGovernPolicyRequest.new(
            policy_rego: Validation.string!(policy_rego, "policy_rego"),
            trigger: trigger.nil? ? "" : Validation.string!(trigger, "trigger")
          )
        )

        response = ::Gitlab::Glaz::Govern::V1::ValidateGovernPolicyResponse.decode(
          native.validate(encoded)
        )

        {
          valid: response.valid,
          errors: response.errors.map { |e| { message: e.message, location: e.location } },
          violation_details: response.violation_details.map { |detail| violation_detail_hash(detail) }
        }
      end

      # Evaluate a Rego query directly, with no `violation`/`deny`/`allow`
      # interpretation and no policy lookup. A debugging escape hatch for
      # policy development: evaluation failures stay in-band on +error+
      # rather than raising.
      #
      # @param policy_rego [String] Rego source (max 64 KiB).
      # @param context [Hash] the Rego `input` document (max 1 MiB as JSON).
      # @param query [String] e.g. "data.mypackage.violation"; must not be
      #   blank.
      # @param data [Hash, nil] optional Rego `data` document, merged as
      #   given.
      # @raise [ArgumentError] for wrong argument types or a document that
      #   does not serialize to JSON.
      # @return [Hash] `{ result: Object, error: String | nil }`. +result+ is
      #   whatever the query evaluated to (parsed JSON, String keys); nil
      #   when +error+ is set.
      def debug_evaluate(policy_rego:, context:, query:, data: nil)
        encoded = ::Gitlab::Glaz::Govern::V1::EvaluateGovernPolicyDebugRequest.encode(
          ::Gitlab::Glaz::Govern::V1::EvaluateGovernPolicyDebugRequest.new(
            policy_rego: Validation.string!(policy_rego, "policy_rego"),
            query: Validation.string!(query, "query"),
            input_json: Validation.json!(context, "context"),
            data_json: data.nil? ? "" : Validation.json!(data, "data")
          )
        )

        response = JSON.parse(native.debug_evaluate(encoded), max_nesting: false)

        {
          result: response["result"],
          error: Validation.presence(response["error"])
        }
      end

      private

      # A forked child inherits the parent's engine and its pooled HTTP
      # sockets, so the first call after a fork rebuilds it. The lock is only
      # taken on that path, so concurrent first calls in the child (a Puma
      # worker's request threads) share one rebuild. Ruby releases a mutex
      # whose owner did not survive the fork, so the child cannot inherit it
      # locked.
      def native
        return @native if @pid == Process.pid

        @rebuild_lock.synchronize do
          if @pid != Process.pid
            @native = build_native
            @pid = Process.pid
          end
        end
        @native
      end

      def require_policy_source!(policies)
        return unless @store_base_url.nil? && policies.nil?

        raise ArgumentError, "this engine has no Policy Store to resolve policies from: pass the policies " \
          "as policies:, pass store_base_url: to Gitlab::Glaz::GovernPolicyEngine.new, or for the " \
          "shared engine assign Gitlab::Glaz::GovernPolicyEngine.policy_store_url or set GLAZ_POLICY_STORE_URL " \
          "(e.g. \"https://gitlab.com/api/v4\")"
      end

      def evaluation_request(trigger, context, principal, resource, data, store_authorization, policies, dry_run:)
        require_policy_source!(policies)

        ::Gitlab::Glaz::Govern::V1::EvaluateGovernPolicyRequest.encode(
          ::Gitlab::Glaz::Govern::V1::EvaluateGovernPolicyRequest.new(
            trigger: Validation.string!(trigger, "trigger"),
            input_json: Validation.json!(context, "context"),
            data_json: data.nil? ? "" : Validation.json!(data, "data"),
            principal: Validation.string!(principal, "principal"),
            resource: Validation.string!(resource, "resource"),
            store_authorization: Validation.store_authorization!(store_authorization),
            policies: Validation.policies!(policies),
            dry_run: dry_run
          )
        )
      end

      def evaluation_result(response)
        {
          decisions: response.decisions.map { |decision| decision_hash(decision) },
          undecided_policy_ids: response.undecided_policy_ids.to_a,
          identifier: response.identifier,
          dry_run: response.dry_run
        }
      end

      def build_native
        ::Glaz::Native::GovernPolicyEngine.new(@store_base_url, @connect_timeout_ms, @timeout_ms)
      end

      def decision_hash(decision)
        {
          policy_id: decision.policy_id,
          matched: decision.matched,
          actions: decision.actions.map { |action| action_hash(action) },
          reasons: decision.reasons.map { |reason| reason_hash(reason) },
          error: Validation.presence(decision.error),
          name: decision.name,
          mode: Validation.mode_name(decision.mode),
          violation_details: decision.violation_details.map { |detail| violation_detail_hash(detail) }
        }
      end

      APPLICABILITIES = {
        APPLICABILITY_APPLIES: "applies",
        APPLICABILITY_NOT_APPLICABLE: "not_applicable",
        APPLICABILITY_MIGHT_APPLY: "might_apply"
      }.freeze
      private_constant :APPLICABILITIES

      # UNSPECIFIED is the engine's "not stated", which it sends only with an
      # error. Without one it would read as an answer, so it is a fault.
      def applicability_hash(row)
        error = Validation.presence(row.error)
        applicability = APPLICABILITIES[row.applicability]
        if applicability.nil? && error.nil?
          raise "policy #{row.policy_id} has no applicability and no error; got #{row.applicability.inspect}"
        end

        {
          policy_id: row.policy_id,
          name: row.name,
          applicability: applicability,
          missing_dimensions: row.missing_dimensions.to_a,
          error: error
        }
      end

      # +expected_json+ may encode a scalar, which json 2 parses as a
      # document; +quirks_mode+ only matters to older json versions.
      def violation_detail_hash(detail)
        return { path: detail.path } if detail.expected_json.empty?

        { path: detail.path, expected: JSON.parse(detail.expected_json, max_nesting: false, quirks_mode: true) }
      end

      # The native layer already bounds nesting, so parse without a limit.
      def action_hash(action)
        {
          action_type: action.action_type,
          message: Validation.presence(action.message),
          params: JSON.parse(action.params_json, max_nesting: false),
          gating: action.gating
        }
      end

      def reason_hash(reason)
        {
          message: Validation.presence(reason.message),
          details: JSON.parse(reason.details_json, max_nesting: false)
        }
      end
    end
  end
end
