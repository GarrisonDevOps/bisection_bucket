# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    module Clients
      module Rest
        extend ActiveSupport::Concern

        class_methods do
          SubscriptionPortalRESTException = Class.new(RuntimeError)

          def generate_trial(params)
            return request_disabled_error unless requests_enabled?

            trial_user_params = params[:trial_user] ? params : { trial_user: params }
            http_post('trials/gitlab_com/ultimates', admin_headers, trial_user_params)
          end

          def generate_self_managed_ultimate_trial(params)
            http_post("trials/self_managed/ultimates", json_headers, params)
          end

          def self_managed_trial_availability
            http_get(
              'trials/self_managed/ultimates/availability',
              json_headers,
              { gitlab_version: ::Gitlab::VERSION },
              timeout: 2.seconds,
              max_retries: 0
            )
          end

          def create_self_managed_welcome_contact(params)
            http_post("leads/self_managed/welcome_contacts", json_headers, params)
          end

          def generate_trial_lead(params)
            return request_disabled_error unless requests_enabled?

            trial_user_params = params[:trial_user] ? params : { trial_user: params }
            http_post("leads/gitlab_com/ultimates", admin_headers, trial_user_params)
          end

          def generate_lead(params)
            return request_disabled_error unless requests_enabled?

            http_post("leads/gitlab_com/hand_raises", admin_headers, params)
          end

          def generate_iterable(params)
            return request_disabled_error unless requests_enabled?

            http_post(iterable_endpoint, admin_headers, params)
          end

          def opt_in_lead(params)
            http_post("api/marketo_leads/opt_in", admin_headers, params)
          end

          def payment_form_params(payment_type, user_id)
            http_get("payment_forms/#{payment_type}", admin_headers, { user_id: user_id }.compact)
          end

          def validate_payment_method(id, params)
            http_post("api/payment_methods/#{id}/validate", admin_headers, params)
          end

          def create_seat_link(seat_link)
            raise TypeError unless seat_link.is_a?(Gitlab::SeatLinkData)

            http_post("api/v1/seat_links", json_headers, seat_link)
          end

          def namespace_eligible_trials(namespace_ids:, timeout: nil, max_retries: nil)
            return request_disabled_error unless requests_enabled?

            http_get(
              'api/v1/gitlab/namespaces/trials/eligibility',
              admin_headers,
              { namespace_ids: namespace_ids },
              timeout: timeout,
              max_retries: max_retries
            )
          end

          def namespace_trial_types(timeout: nil, max_retries: nil)
            return request_disabled_error unless requests_enabled?

            http_get(
              'api/v1/gitlab/namespaces/trials/trial_types',
              admin_headers,
              {},
              timeout: timeout,
              max_retries: max_retries
            )
          end

          # Limits only the connection attempt; the read keeps the Gitlab::HTTP default.
          USAGE_QUOTA_HTTP_OPEN_TIMEOUT_SECONDS = 2.0

          def verify_usage_quota(params)
            headers = if Gitlab.com? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- Available on gitlab.com only
                        admin_headers
                      else
                        license_checksum_headers
                      end

            http_head(
              'api/v1/consumers/resolve', headers, params,
              base_url_to_call: usage_quota_base_url, open_timeout: USAGE_QUOTA_HTTP_OPEN_TIMEOUT_SECONDS
            )
          end

          # Fallback cross-request cache TTL when CDot's Cache-Control header
          # carries no max-age; deliberately short and easy to tune.
          CDOT_CACHE_FALLBACK_TTL = 120.seconds

          # RawTrialPayload: `raw` response body from `GET /trials`, plus cache_ttl from
          # the response's Cache-Control header.
          #   - cached cross-request. The value is valid within `cache_ttl`.
          # SecretsManagerTrialResponse: parsed values, with derived value `state`.
          #   - cached at the SafeRequestStore level. The derived value is valid in the same request.
          #   - `state` is a function of `Time.current`, so it is not safe to cache cross-request.
          RawTrialPayload = Data.define(:payload, :cache_ttl)

          # `fresh: true` skips both cache layers but still stores the answer, so a
          # failed call leaves the previous answer in place.
          def secrets_manager_trial(namespace_id: nil, instance_id: nil, timeout: nil, fresh: false)
            validate_cdot_identifiers!(namespace_id, instance_id)
            key = secrets_manager_cache_key(:trial, namespace_id, instance_id)
            ::Gitlab::SafeRequestStore.delete(key) if fresh

            ::Gitlab::SafeRequestStore.fetch(key) do
              parsed = nil
              cached = cdot_cross_request_cache(key, fresh: fresh) do
                # Parsed before it is cached, so a malformed body never replaces a good answer.
                fetch_secrets_manager_trial(namespace_id: namespace_id, instance_id: instance_id, timeout: timeout)
                  .tap { |raw| parsed = parse_secrets_manager_trial(raw.payload, cache_ttl: raw.cache_ttl) }
              end

              # Parsed once per request, so `state` is stable within a request.
              parsed || parse_secrets_manager_trial(cached.payload, cache_ttl: cached.cache_ttl)
            end
          end

          def secrets_manager_consumer_resolve(
            namespace_id: nil, instance_id: nil, user_id: nil, timeout: nil, fresh: false
          )
            validate_cdot_identifiers!(namespace_id, instance_id)
            key = secrets_manager_cache_key(:consumer_resolve, namespace_id, instance_id)
            ::Gitlab::SafeRequestStore.delete(key) if fresh

            ::Gitlab::SafeRequestStore.fetch(key) do
              cdot_cross_request_cache(key, fresh: fresh) do
                fetch_secrets_manager_consumer_resolve(
                  namespace_id: namespace_id, instance_id: instance_id, user_id: user_id, timeout: timeout
                )
              end
            end
          end

          # POST counterpart to `secrets_manager_trial`: asks CDot to start a
          # Secrets Manager trial. Unlike the GETs this is a state change, so it
          # is never memoized via SafeRequestStore. Eligibility is enforced
          # server-side by CDot's `Billing::Usage::Trials::EligibilityService`;
          # this method only forwards and normalizes the outcome.
          def start_secrets_manager_trial(namespace_id: nil, instance_id: nil)
            validate_cdot_identifiers!(namespace_id, instance_id)

            post_secrets_manager_trial(namespace_id: namespace_id, instance_id: instance_id)
          end

          # A blocked resolve stays cacheable for minutes while granted answers
          # are not cached at all, so a caller that changes the CDot state has to
          # drop these entries or the stale block outlives the change.
          def expire_secrets_manager_cache(namespace_id: nil, instance_id: nil)
            [:trial, :consumer_resolve].each do |endpoint|
              key = secrets_manager_cache_key(endpoint, namespace_id, instance_id)

              ::Gitlab::SafeRequestStore.delete(key)
              Rails.cache.delete(key)
            end
          end

          def product_trial(trial_type:, namespace_id: nil, instance_id: nil, timeout: nil)
            validate_cdot_identifiers!(namespace_id, instance_id)
            key = product_trial_cache_key(trial_type, namespace_id, instance_id)

            ::Gitlab::SafeRequestStore.fetch(key) do
              cached = cdot_cross_request_cache(key) do
                fetch_product_trial(namespace_id: namespace_id, instance_id: instance_id, timeout: timeout)
              end

              # Parsed once per request, so `state` is stable within a request.
              parse_product_trial(trial_type, cached.payload, cache_ttl: cached.cache_ttl)
            end
          end

          # Not cached, because this call starts a trial in CDot.
          def start_product_trial(trial_type:, namespace_id: nil, instance_id: nil)
            validate_cdot_identifiers!(namespace_id, instance_id)

            post_product_trial(trial_type, namespace_id: namespace_id, instance_id: instance_id)
          end

          def expire_product_trial_cache(trial_type:, namespace_id: nil, instance_id: nil)
            key = product_trial_cache_key(trial_type, namespace_id, instance_id)

            ::Gitlab::SafeRequestStore.delete(key)
            Rails.cache.delete(key)
          end

          private

          def fetch_product_trial(namespace_id:, instance_id:, timeout: nil)
            url = "#{base_url}/api/v1/billing/usage/trials"
            query = cdot_trial_query(namespace_id: namespace_id, instance_id: instance_id)

            options = { query: query, headers: cdot_identity_headers }
            options[:timeout] = timeout if timeout

            response = ::Gitlab::HTTP.get(url, options)
            if response.code == 200
              return RawTrialPayload.new(payload: response.parsed_response, cache_ttl: extract_cache_ttl(response))
            end

            raise cdot_status_error(::Gitlab::SubscriptionPortal::ProductTrialResponse, response)
          rescue *::Gitlab::HTTP::HTTP_ERRORS => e
            raise cdot_transport_error(::Gitlab::SubscriptionPortal::ProductTrialResponse, e)
          end

          # CDot owns eligibility, so we translate its HTTP status into a result:
          #   200 / 201 -> success
          #   409       -> a trial exists, active or expired (:trial_already_active)
          #   422       -> rejected as ineligible (:ineligible, reason from body)
          #   404       -> namespace/instance unknown to CDot (:not_found)
          #   anything else -> protocol/deployment error, raise
          def post_product_trial(trial_type, namespace_id:, instance_id:)
            url = "#{base_url}/api/v1/billing/usage/trials"
            body = cdot_trial_query(namespace_id: namespace_id, instance_id: instance_id)
              .merge(trial_type: trial_type.to_s)

            response = ::Gitlab::HTTP.post(url, body: body.to_json, headers: cdot_identity_headers)

            case response.code
            when 200, 201
              ::Gitlab::SubscriptionPortal::StartProductTrialResponse.new(success: true)
            when 409
              ::Gitlab::SubscriptionPortal::StartProductTrialResponse.new(
                success: false, error_code: :trial_already_active
              )
            when 422
              ::Gitlab::SubscriptionPortal::StartProductTrialResponse.new(
                success: false,
                error_code: :ineligible,
                error_message: parse_start_trial_error_message(response)
              )
            when 404
              ::Gitlab::SubscriptionPortal::StartProductTrialResponse.new(success: false, error_code: :not_found)
            else
              raise ::Gitlab::SubscriptionPortal::StartProductTrialResponse::Error,
                "Unexpected CDot response: HTTP #{response.code}"
            end
          rescue *::Gitlab::HTTP::HTTP_ERRORS, ::Gitlab::HTTP::SilentModeBlockedError => e
            raise ::Gitlab::SubscriptionPortal::StartProductTrialResponse::Error, e.message
          end

          def parse_product_trial(trial_type, payload, cache_ttl: nil)
            payload = coerce_cdot_payload!(payload, ::Gitlab::SubscriptionPortal::ProductTrialResponse::Error)
            trial_info = payload.dig(:trial_info, trial_type)

            unless trial_info.is_a?(Hash)
              return ::Gitlab::SubscriptionPortal::ProductTrialResponse.new(state: :ineligible, cache_ttl: cache_ttl)
            end

            # Active grants of a trial share one expiry; grants that expire earlier belong to an earlier trial.
            trials = Array.wrap(trial_info[:trials])
            expires_at = trials.filter_map { |trial| parse_time(trial[:expires_at]) }.max
            current_grants = trials.select { |trial| parse_time(trial[:expires_at]) == expires_at }
            offer = trial_info[:default_trial_offer]
            offer = {} unless offer.is_a?(Hash)

            ::Gitlab::SubscriptionPortal::ProductTrialResponse.new(
              state: derive_trial_state(trial_info, current_grants.first),
              trial_started_at: current_grants.filter_map { |trial| parse_time(trial[:starts_at]) }.min,
              trial_expires_at: expires_at,
              credits_remaining: parse_credit_amount(trial_info[:current_balance]),
              credits_total: sum_credit_amounts(current_grants),
              on_demand_enabled: trial_info[:opt_in_paid],
              offer_duration_days: positive_or_nil(Integer(offer[:duration_days], exception: false)),
              offer_credits: positive_or_nil(Float(offer[:initial_credit_amount], exception: false)),
              cache_ttl: cache_ttl
            )
          end

          def product_trial_cache_key(trial_type, namespace_id, instance_id)
            if saas?
              [:product_trial, trial_type.to_sym, :namespace_id, namespace_id]
            else
              [:product_trial, trial_type.to_sym, :instance_id, instance_id]
            end
          end

          # Cross-request TTL cache for the CDot entitlement GETs, so read
          # volume (one OpenBao audit callback per secret read) does not
          # translate 1:1 into CDot request volume. TTL honors CDot's
          # Cache-Control max-age when present (0 disables caching); failures
          # raise before the write, so errors are never cached.
          def cdot_cross_request_cache(key, fresh: false)
            unless fresh
              cached = Rails.cache.read(key)
              return cached unless cached.nil?
            end

            yield.tap do |response|
              ttl = response.cache_ttl&.seconds || CDOT_CACHE_FALLBACK_TTL

              if ttl > 0
                Rails.cache.write(key, response, expires_in: ttl)
              elsif fresh
                # Nothing replaces the old entry here, so drop it rather than serve it.
                Rails.cache.delete(key)
              end
            end
          end

          def fetch_secrets_manager_trial(namespace_id:, instance_id:, timeout: nil)
            url = "#{base_url}/api/v1/billing/usage/trials"
            headers = cdot_identity_headers
            query = cdot_trial_query(namespace_id: namespace_id, instance_id: instance_id)

            options = { query: query, headers: headers }
            options[:timeout] = timeout if timeout

            response = ::Gitlab::HTTP.get(url, options)
            if response.code == 200
              return RawTrialPayload.new(payload: response.parsed_response, cache_ttl: extract_cache_ttl(response))
            end

            raise cdot_status_error(::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse, response)
          rescue *::Gitlab::HTTP::HTTP_ERRORS => e
            raise cdot_transport_error(::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse, e)
          rescue JSON::ParserError => e
            # HTTParty parses lazily, so a 200 with a non-JSON body only fails here.
            raise ::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse::Error,
              "Unexpected CDot payload: #{e.message}"
          end

          # CDot's `Api::V1::Consumers::ResolveController` is feature-scoped
          # (the caller declares which feature is being authorized) and signals
          # the verdict via HTTP status, not a body field:
          #
          #   HTTP 200             -> not blocked
          #   HTTP 402 (PAYMENT)   -> blocked, body carries `block_reason`
          #   HTTP 5xx / no reply  -> CDot unavailable, raise UnavailableError
          #   anything else        -> protocol/deployment error, raise
          #
          # A 403 here also carries a block_reason (resolution_error when CDot couldn't
          # resolve the consumer); it's raised like any other status, reason rides along.
          #
          # Required query params: `feature_qualified_name`, `realm`,
          # `instance_version`, `user_id` (the requesting actor), and the
          # identifier (`root_namespace_id` on SaaS, `instance_id` +
          # `unique_instance_id` on self-managed online cloud).
          def fetch_secrets_manager_consumer_resolve(namespace_id:, instance_id:, user_id:, timeout: nil)
            url = "#{base_url}/api/v1/consumers/resolve"
            headers = cdot_identity_headers
            query = cdot_consumer_resolve_query(
              namespace_id: namespace_id, instance_id: instance_id, user_id: user_id
            )

            options = { query: query, headers: headers }
            options[:timeout] = timeout if timeout

            response = ::Gitlab::HTTP.get(url, options)

            case response.code
            when 200
              ::Gitlab::SubscriptionPortal::SecretsManagerConsumerResolveResponse.new(
                blocked: false, cache_ttl: extract_cache_ttl(response)
              )
            when 402
              parse_secrets_manager_consumer_resolve_blocked(
                response.parsed_response, cache_ttl: extract_cache_ttl(response)
              )
            else
              raise cdot_status_error(::Gitlab::SubscriptionPortal::SecretsManagerConsumerResolveResponse, response)
            end
          rescue *::Gitlab::HTTP::HTTP_ERRORS => e
            raise cdot_transport_error(::Gitlab::SubscriptionPortal::SecretsManagerConsumerResolveResponse, e)
          end

          # The client owns the "was CDot unavailable" call: callers may treat the response
          # class's UnavailableError as an outage, its plain Error fails closed.
          def cdot_transport_error(response_class, error)
            if ::Gitlab::SubscriptionPortal::CdotResponseError.unavailable_transport?(error)
              response_class::UnavailableError.new(error.message)
            else
              response_class::Error.new(error.message)
            end
          end

          def cdot_status_error(response_class, response)
            code = response.code
            block_reason = cdot_body_block_reason(response)

            if ::Gitlab::SubscriptionPortal::CdotResponseError.unavailable_status?(code)
              response_class::UnavailableError.new(
                "CDot unavailable: HTTP #{code}", cdot_status: code, cdot_block_reason: block_reason
              )
            else
              response_class::Error.new(
                "Unexpected CDot response: HTTP #{code}", cdot_status: code, cdot_block_reason: block_reason
              )
            end
          end

          # nginx error pages are HTML, and HTTParty only parses JSON lazily, so a
          # non-Hash or unparseable body just means there's no reason to report.
          def cdot_body_block_reason(response)
            payload = response.parsed_response
            return unless payload.is_a?(Hash)

            payload.with_indifferent_access[:block_reason].presence&.to_s
          rescue JSON::ParserError
            nil
          end

          # POST to the same `/billing/usage/trials` endpoint as the GET, with
          # the env-routed identifier + realm in the body. CDot owns eligibility,
          # so we translate its HTTP status into a normalized result:
          #
          #   200 / 201 -> success
          #   409       -> already trialing (:trial_already_active)
          #   422       -> rejected as ineligible (:ineligible, message from body)
          #   404       -> namespace/instance unknown to CDot (:not_found)
          #   anything else -> protocol/deployment error, raise (mutation maps
          #                    this to a generic "unavailable" message)
          def post_secrets_manager_trial(namespace_id:, instance_id:)
            url = "#{base_url}/api/v1/billing/usage/trials"
            headers = cdot_identity_headers
            body = cdot_trial_query(namespace_id: namespace_id, instance_id: instance_id)
              .merge(trial_type: 'secrets_manager')

            response = ::Gitlab::HTTP.post(url, body: body.to_json, headers: headers)

            case response.code
            when 200, 201
              ::Gitlab::SubscriptionPortal::SecretsManagerStartTrialResponse.new(success: true)
            when 409
              ::Gitlab::SubscriptionPortal::SecretsManagerStartTrialResponse.new(
                success: false, error_code: :trial_already_active
              )
            when 422
              ::Gitlab::SubscriptionPortal::SecretsManagerStartTrialResponse.new(
                success: false,
                error_code: :ineligible,
                error_message: parse_start_trial_error_message(response)
              )
            when 404
              ::Gitlab::SubscriptionPortal::SecretsManagerStartTrialResponse.new(
                success: false, error_code: :not_found
              )
            else
              raise ::Gitlab::SubscriptionPortal::SecretsManagerStartTrialResponse::Error,
                "Unexpected CDot response: HTTP #{response.code}"
            end
          # Silent mode blocks the POST outside HTTP_ERRORS; self-managed is the
          # first caller that can hit it.
          rescue *::Gitlab::HTTP::HTTP_ERRORS, ::Gitlab::HTTP::SilentModeBlockedError => e
            raise ::Gitlab::SubscriptionPortal::SecretsManagerStartTrialResponse::Error, e.message
          end

          # CDot's 422 body carries a human-readable reason under `errors`
          # (string or array). Returns nil when the body is unparseable so the
          # mutation falls back to a generic message; the 422 itself still means
          # ineligible, so a parse failure must not become "unavailable".
          def parse_start_trial_error_message(response)
            payload = response.parsed_response
            return unless payload.is_a?(Hash)

            errors = payload.with_indifferent_access[:errors]
            Array.wrap(errors).join(', ').presence
          rescue JSON::ParserError => e
            # Contract drift on CDot's side; report it, but keep the 422 classified as ineligible.
            ::Gitlab::ErrorTracking.track_exception(e, cdot_status: response.code)
            nil
          end

          # CDot's GET /api/v1/billing/usage/trials returns raw trial facts
          # (trial history, current credit balance, paid opt-in, new-trial
          # eligibility) for ALL trial add-ons under `trial_info`. It does NOT
          # return a lifecycle `state` field, so we derive ours here from the
          # secrets_manager sub-block:
          #
          #   no SM block (CDot disabled trial provisioning) -> :ineligible
          #   no trials                  -> :trial_eligible if eligible, else :ineligible
          #   trials[0].expires_at >= now -> :trial
          #   trials[0].expires_at <  now -> :expired
          #
          # As of today only one secrets_manager trial per namespace is allowed,
          # so we read `trials[0]`; the array shape is preserved by CDot for
          # forward compatibility (multiple trial periods).
          #
          # Quota fields also live here (not on /consumers/resolve):
          #   current_balance              -> credits_remaining (coerced to Float)
          #   trials[0].initial_credit_amount -> credits_total      (coerced to Float)
          #   opt_in_paid                  -> on_demand_enabled
          def parse_secrets_manager_trial(payload, cache_ttl: nil)
            payload = coerce_cdot_payload!(payload, ::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse::Error)
            sm = payload.dig(:trial_info, :secrets_manager)

            unless sm.is_a?(Hash)
              return ::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse.new(
                state: :ineligible, cache_ttl: cache_ttl
              )
            end

            current_trial = Array.wrap(sm[:trials]).first

            ::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse.new(
              state: derive_trial_state(sm, current_trial),
              trial_started_at: parse_time(current_trial&.dig(:starts_at)),
              trial_expires_at: parse_time(current_trial&.dig(:expires_at)),
              credits_remaining: parse_credit_amount(sm[:current_balance]),
              credits_total: parse_credit_amount(current_trial&.dig(:initial_credit_amount)),
              on_demand_enabled: sm[:opt_in_paid],
              cache_ttl: cache_ttl
            )
          rescue TypeError, NoMethodError => e
            # A body of the wrong shape (e.g. a String where a Hash belongs) is a CDot error, not a bug here.
            raise ::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse::Error,
              "Unexpected CDot payload: #{e.message}"
          end

          def derive_trial_state(trial_info, current_trial)
            if current_trial.blank?
              trial_info[:eligible_to_start_new_trial] ? :trial_eligible : :ineligible
            else
              expires_at = parse_time(current_trial[:expires_at])
              expires_at && expires_at >= Time.current ? :trial : :expired
            end
          end

          # CDot returns credit amounts as stringified decimals (e.g. "500.0").
          # Keep full precision: truncating would misreport any balance in
          # (0, 1) as 0, which the frontend treats as credits exhausted.
          def parse_credit_amount(value)
            return if value.nil?

            value.to_f
          end

          def sum_credit_amounts(trials)
            return if trials.empty?

            trials.sum { |trial| trial[:initial_credit_amount].to_f }
          end

          def positive_or_nil(number)
            number if number&.positive?
          end

          # Only called for HTTP 402 responses. CDot's body carries the reason
          # as the singular `block_reason` field. Unknown values are parsed
          # as-is; the resolver fails closed on reasons it cannot map.
          def parse_secrets_manager_consumer_resolve_blocked(payload, cache_ttl: nil)
            payload = coerce_cdot_payload!(payload, ::Gitlab::SubscriptionPortal::SecretsManagerConsumerResolveResponse::Error)

            ::Gitlab::SubscriptionPortal::SecretsManagerConsumerResolveResponse.new(
              blocked: true,
              blocked_reason: payload[:block_reason]&.to_sym,
              cache_ttl: cache_ttl
            )
          end

          def coerce_cdot_payload!(payload, error_class)
            raise error_class, "Unexpected CDot payload: #{payload.class}" unless payload.is_a?(Hash)

            payload.with_indifferent_access
          end

          # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- CDot identity is env-determined: token, query identifier, cache axis, and validator all key off this
          def saas?
            ::Gitlab.com?
          end
          # rubocop:enable Gitlab/AvoidGitlabInstanceChecks

          # Auth identity is environment-driven, not arg-driven: on gitlab.com
          # we authenticate with the admin token; on self-managed online cloud
          # installs the license checksum is the only credential available.
          def cdot_identity_headers
            base = saas? ? admin_headers : license_checksum_headers
            base.merge('X-Gitlab-Version' => ::Gitlab::VERSION)
          end

          def cdot_realm
            saas? ? 'saas' : 'self-managed'
          end

          # On SaaS CDot keys trials by the top-level namespace and expects the
          # `root_namespace_id` param (not `namespace_id`); self-managed online
          # cloud installs are keyed by `instance_id`.
          def cdot_identifier_query(namespace_id:, instance_id:)
            saas? ? { root_namespace_id: namespace_id } : { instance_id: instance_id }
          end

          # `/billing/usage/trials` requires the realm alongside the identifier.
          def cdot_trial_query(namespace_id:, instance_id:)
            cdot_identifier_query(namespace_id: namespace_id, instance_id: instance_id)
              .merge(realm: cdot_realm)
          end

          # `/consumers/resolve` is feature-scoped, version-aware, and
          # actor-aware, so it needs more than just the identifier. The realm
          # and instance_version pair lets CDot apply min-version gating;
          # `user_id` is the requesting actor. Self-managed installs
          # additionally send `unique_instance_id` (the instance UUID).
          # `event_type` and `feature_qualified_name` use CDot's flow-type
          # vocabulary (the same one our usage-event emitters use) so CDot can
          # classify the consumer and resolve the workflow.
          def cdot_consumer_resolve_query(namespace_id:, instance_id:, user_id:)
            query = cdot_identifier_query(namespace_id: namespace_id, instance_id: instance_id).merge(
              realm: cdot_realm,
              event_type: 'secrets_read',
              feature_qualified_name: 'secrets_read',
              instance_version: ::Gitlab::VERSION,
              user_id: user_id
            )
            query[:unique_instance_id] = instance_id unless saas?

            query
          end

          def validate_cdot_identifiers!(namespace_id, instance_id)
            if saas?
              return if namespace_id.present? && instance_id.blank?

              raise ArgumentError,
                'This CDot call on gitlab.com requires namespace_id only ' \
                  "(got namespace_id=#{namespace_id.inspect}, instance_id=#{instance_id.inspect})"
            else
              return if instance_id.present? && namespace_id.blank?

              raise ArgumentError,
                'This CDot call on self-managed requires instance_id only ' \
                  "(got namespace_id=#{namespace_id.inspect}, instance_id=#{instance_id.inspect})"
            end
          end

          # Key shape preserves the axis (`:namespace_id` vs `:instance_id`)
          # alongside the value so an integer namespace_id and a UUID
          # instance_id can never collide in the per-request cache, even if
          # they happened to be equal. The axis is env-driven, matching
          # cdot_identity_headers / cdot_identifier_query.
          def secrets_manager_cache_key(endpoint, namespace_id, instance_id)
            if saas?
              [:secrets_manager, endpoint, :namespace_id, namespace_id]
            else
              [:secrets_manager, endpoint, :instance_id, instance_id]
            end
          end

          def parse_time(value)
            return if value.blank?

            Time.zone.parse(value.to_s)
          rescue ArgumentError
            nil
          end

          def requests_enabled?
            ::Gitlab::Saas.feature_available?(:cdot_requests)
          end

          def iterable_endpoint
            return "leads/gitlab_com/iterables" if Feature.enabled?(:new_iterable_lead_endpoint, :instance)

            "trials/create_iterable"
          end

          def error_message
            _('Our team has been notified. Please try again.')
          end

          def request_disabled_error
            {
              success: false,
              data: { errors: 'Subscription portal requests disabled for non-SaaS.' }
            }.with_indifferent_access
          end

          def track_exception(message)
            Gitlab::ErrorTracking.track_exception(SubscriptionPortalRESTException.new(message))
          end

          def base_url
            ::Gitlab::Routing.url_helpers.subscription_portal_url
          end

          def http_get(path, headers, query = {}, timeout: nil, max_retries: nil)
            options = { query: query, headers: headers }
            options[:timeout] = timeout if timeout
            options[:max_retries] = max_retries if max_retries

            process_http_call { Gitlab::HTTP.get("#{base_url}/#{path}", **options) }
          end

          def http_post(path, headers, params = {})
            process_http_call do
              Gitlab::HTTP.post("#{base_url}/#{path}", body: params.to_json, headers: headers)
            end
          end

          def http_head(path, headers, query = {}, open_timeout:, base_url_to_call: base_url)
            options = { query: query, headers: headers, open_timeout: open_timeout }

            process_http_call do
              Gitlab::HTTP.head("#{base_url_to_call}/#{path}", options)
            end
          end

          def process_http_call
            response = yield
            parse_response(response).tap do |result|
              result[:cache_ttl] = extract_cache_ttl(response)
              result[:status] = response.code
              result[:unavailable] = ::Gitlab::SubscriptionPortal::CdotResponseError.unavailable_status?(response.code)
            end
          rescue *Gitlab::HTTP::HTTP_ERRORS => e
            track_exception(e.message)
            {
              success: false,
              data: { errors: error_message },
              unavailable: ::Gitlab::SubscriptionPortal::CdotResponseError.unavailable_transport?(e)
            }.with_indifferent_access
          end

          def extract_cache_ttl(response)
            cache_control = response.headers&.[]('cache-control')
            return unless cache_control

            match = cache_control.match(/max-age=(\d+)/)
            match[1].to_i if match
          end

          def usage_quota_base_url
            return base_url unless use_mock_usage_quota_endpoint?

            env_url = ENV['MOCK_CUSTOMER_DOT_PORTAL_SERVER_URL']
            return env_url if env_url.present?

            'http://localhost:4567'
          end

          def use_mock_usage_quota_endpoint?
            Rails.env.development? &&
              Feature.enabled?(:use_mock_dot_api_for_usage_quota, :instance)
          end
        end
      end
    end
  end
end
