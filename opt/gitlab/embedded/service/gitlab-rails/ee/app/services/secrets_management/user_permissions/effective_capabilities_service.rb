# frozen_string_literal: true

module SecretsManagement
  module UserPermissions
    # Resolves the effective OpenBao capabilities for a user on a secrets manager resource.
    #
    # Uses the user-scoped client (CEL login with ProjectUserJwt / GroupUserJwt) to call
    # `sys/capabilities-self`, letting OpenBao compute the union of all applicable principal
    # policies (user, member-role, role).
    #
    # The GraphQL `userPermissions` field calls this on every secrets page load, so the
    # OpenBao lookup (three round trips) is cached via `Gitlab::Cache.fetch_once` (Redis
    # for cross-request, SafeRequestStore within a request). Entitlement is re-applied on
    # every call because it changes independently of OpenBao; caching it would freeze a
    # billing decision.
    #
    # Path mapping (mirrors update_service_helpers.rb):
    #   - readMetadata  from `list` on the detailed-metadata path (detailed_metadata_path('*')),
    #     the path the secrets list service actually reads
    #   - createSecrets from `create` on the data path (ci_full_path('*'))
    #   - updateSecrets from `update` on the data path (ci_full_path('*'))
    #   - deleteSecrets from `delete` on the data path (ci_full_path('*'))
    #
    # `read_value` is intentionally not resolved here: it lives on a separate
    # `api_jwt` mount/policy (see !240364) that this user-scoped client does not
    # authenticate against. Its GraphQL exposure is tracked in #602726.
    #
    # Any OpenBao error is rescued and returns all-false (fail closed), and is
    # reported to Sentry once the secrets manager is active.
    #
    # Returns a hash with boolean values for each capability:
    #   { "read_metadata" => bool, "create" => bool, "update" => bool, "delete" => bool }
    class EffectiveCapabilitiesService
      EXPOSED_CAPABILITIES = %w[read_metadata create update delete].freeze

      # Bump when the cached payload or the path mapping below changes.
      CACHE_VERSION = 1

      # Rails cannot know when OpenBao policies change, so expiry is the only
      # thing that bounds how long a revoked grant keeps working.
      CACHE_TTL = 30.seconds

      # Per request; the lookup makes three in a row (login, capabilities, revoke). A timeout
      # returns all-false, which the UI shows as "no read access", so don't make it too short.
      DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0

      # @param secrets_manager [SecretsManagement::BaseSecretsManager]
      # @param current_user [User]
      # @param resource [Project, Group] the project or group owning the secrets manager
      # @param http_timeout [Numeric, nil] per-request OpenBao timeout in seconds;
      #   nil keeps the client defaults
      def initialize(secrets_manager:, current_user:, resource:, http_timeout: DEFAULT_HTTP_TIMEOUT_SECONDS)
        @secrets_manager = secrets_manager
        @current_user = current_user
        @resource = resource
        @http_timeout = http_timeout
      end

      # @return [Hash<String, Boolean>] e.g. { "read_metadata" => true, "create" => false, ... }
      def execute
        # Before activation the default role policies may not exist yet, so a
        # lookup can succeed with an all-deny answer that would then be cached
        # past activation (the status poll on the secrets page hits this
        # window). Answer without asking or caching until the manager is active.
        return all_false unless secrets_manager.active_after_refresh?

        capabilities = cached_openbao_capabilities
        return all_false if capabilities.nil?

        reads_permitted = entitlement_permits_reads?
        writes_permitted = !strict_read_only? && entitlement_permits_writes?
        # The billing entitlement gates deletes like reads, see `Entitlement#permits_read?`.
        # The OpenBao `delete` capability below is still what grants the action.
        deletes_permitted = !strict_read_only? && reads_permitted

        {
          'read_metadata' => capabilities['read_metadata'] && reads_permitted,
          'create' => capabilities['create'] && writes_permitted,
          'update' => capabilities['update'] && writes_permitted,
          'delete' => capabilities['delete'] && deletes_permitted
        }
      end

      private

      attr_reader :secrets_manager, :current_user, :resource, :http_timeout

      # skip_nil: true prevents a failed lookup (nil) from being written to Redis,
      # so the next request retries OpenBao. Within the current request, SafeRequestStore
      # pins the nil, so a second caller in the same request does not retry.
      def cached_openbao_capabilities
        ::Gitlab::Cache.fetch_once(cache_key, expires_in: CACHE_TTL, skip_nil: true) do
          fetch_openbao_capabilities
        end
      end

      def cache_key
        self.class.cache_key_for(secrets_manager: secrets_manager, user_id: current_user.id)
      end

      class << self
        # A grant to a named user maps to exactly one entry, so the permission services drop it and
        # the change is visible at once instead of after CACHE_TTL. Role, group and custom-role
        # grants fan out to members that cannot be enumerated cheaply and keep relying on expiry.
        def expire_for_user(secrets_manager:, user_id:)
          key = cache_key_for(secrets_manager: secrets_manager, user_id: user_id)

          ::Gitlab::SafeRequestStore.delete(key)
          Rails.cache.delete(key)
        end

        # The user is part of the key because the CEL program derives the applicable
        # policies from user_id, member_role_id, groups and role_id, so a key without
        # the user would serve one user's capabilities to another. `scope_name` is
        # needed alongside the ID because project and group managers are separate
        # tables whose IDs collide.
        def cache_key_for(secrets_manager:, user_id:)
          [
            'secrets_management', 'effective_capabilities', CACHE_VERSION,
            secrets_manager.scope_name, secrets_manager.id, user_id
          ]
        end
      end

      # Returns nil on any OpenBao error so `skip_nil` keeps the failure out of the
      # cache; a transient blip must not deny the user for the whole TTL.
      #
      # @return [Hash<String, Boolean>, nil] pre-entitlement capabilities
      def fetch_openbao_capabilities
        data_path = secrets_manager.ci_full_path('*')
        detailed_metadata_path = secrets_manager.detailed_metadata_path('*')

        response = user_scoped_client.capabilities_self(paths: [data_path, detailed_metadata_path])

        # OpenBao returns the per-path capability map under the "data" envelope.
        # (Non-namespaced responses also mirror it at the top level, but namespaced
        # ones only populate "data", so always read from there.)
        per_path = response&.dig("data") || {}
        data_caps = Array(per_path[data_path])
        detailed_metadata_caps = Array(per_path[detailed_metadata_path])

        {
          'read_metadata' => detailed_metadata_caps.include?('list'),
          'create' => data_caps.include?('create'),
          'update' => data_caps.include?('update'),
          'delete' => data_caps.include?('delete')
        }
      rescue SecretsManagement::SecretsManagerClient::ApiError,
        SecretsManagement::SecretsManagerClient::ConnectionError,
        SecretsManagement::SecretsManagerClient::ServiceUnavailableError,
        SecretsManagement::SecretsManagerClient::AuthenticationError => e
        report_capability_failure(e)
        nil
      end

      # Outside `active` the user auth mount does not exist in OpenBao yet, so a
      # failure is the provisioning window rather than a fault. Once active, a
      # user with no grant gets a successful response listing `deny`, so anything
      # that raises means the JWT, the CEL role or OpenBao itself is broken.
      def report_capability_failure(error)
        return unless secrets_manager.active?

        ::SecretsManagement::ThrottledErrorTracking.track_exception(
          error, throttle_key: :effective_capabilities_fail_closed, gl_namespace_id: resource.root_ancestor.id
        )
      end

      # @return [SecretsManagerClient] a client authenticated as the current user via CEL login
      def user_scoped_client
        raise Gitlab::AbstractMethodError
      end

      def all_false
        EXPOSED_CAPABILITIES.index_with { false }
      end

      # Mirror the mutation-side entitlement gate in `EnforcesWriteEntitlement` so
      # the booleans exposed on `userPermissions` reflect what the resolvers and
      # mutations will actually accept.
      def entitlement_permits_reads?
        entitlement.permits_read?
      end

      def entitlement_permits_writes?
        entitlement.permits_writes?
      end

      # Same guard as `Mutations::BaseMutation#ready?`, so the booleans match what
      # the mutations will accept on a Geo secondary or in maintenance mode.
      def strict_read_only?
        ::Gitlab::Database.read_only?
      end

      # `Entitlement.for` is request-cached (SafeRequestStore), so resolving it
      # for both the read and write gates costs one lookup.
      def entitlement
        root_namespace = ::SecretsManagement::Entitlement.root_namespace_for(resource)
        ::SecretsManagement::Entitlement.for(root_namespace, user: current_user)
      end
    end
  end
end
