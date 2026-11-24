# frozen_string_literal: true

module Analytics
  module CustomDashboards
    # Constraints a dashboard must satisfy before it is shown, declared per
    # dashboard under the `constraints` key in its YAML.
    #
    # Each kind is a separate key rather than one list of tokens, so that the
    # JSON schema can validate each on its own terms, and so a caller can tell
    # a missing licence apart from a disabled feature flag -- those want
    # different treatment, an upsell versus hiding the dashboard entirely.
    class DashboardConstraints
      DATA_CHECKS = {
        'clickhouse' => -> { ::Gitlab::ClickHouse.globally_enabled_for_analytics? }
      }.freeze

      # The flag name has to appear as a literal symbol for the feature flag
      # tooling and the Gitlab/FeatureFlagKeyDynamic cop to find it, so a
      # dashboard names a token here rather than the flag itself.
      #
      # `dap_impact_v1` takes users and root groups as actors, so a customer can
      # be enabled as a whole: membership of an enabled root group is enough.
      # Membership is only queried once some group has the flag.
      FEATURE_FLAG_CHECKS = {
        'dap_impact_v1' => ->(user) {
          ::Feature.enabled?(:dap_impact_v1, user) ||
            (group_actors?(:dap_impact_v1) &&
              root_group_actors(user).any? { |group| ::Feature.enabled?(:dap_impact_v1, group) })
        },
        'gi_migration_dora_metrics' => ->(user) { ::Feature.enabled?(:gi_migration_dora_metrics, user) },
        'gi_migration_merge_request_analytics' => ->(user) {
          ::Feature.enabled?(:gi_migration_merge_request_analytics, user)
        },
        'gi_migration_value_streams_dashboard' => ->(user) {
          ::Feature.enabled?(:gi_migration_value_streams_dashboard, user) ||
            (group_actors?(:gi_migration_value_streams_dashboard) &&
              root_group_actors(user).any? { |group| ::Feature.enabled?(:gi_migration_value_streams_dashboard, group) })
        }
      }.freeze

      # The licensed features the JSON schema allows under `license`.
      LICENSED_FEATURES = %w[
        product_analytics
        group_level_analytics_dashboard
        project_level_analytics_dashboard
      ].freeze

      # The keys the JSON schema allows under `constraints`.
      KINDS = %w[license feature_flag data].freeze

      def self.satisfied?(dashboard, user)
        new(dashboard, user).satisfied?
      end

      # Read through Flipper's cache, like `Feature.enabled?`. `Feature.group_ids_for`
      # queries the gates table directly on every call.
      def self.group_actors?(flag)
        feature = ::Feature.get(flag) # rubocop:disable Gitlab/AvoidFeatureGet -- read-only actor list, see above

        feature.actors_value.any? { |flipper_id| flipper_id.start_with?('Group:') }
      end
      private_class_method :group_actors?

      # Roots of every authorized group, so a subgroup-only member still counts,
      # matching the API. One query; the flag's gates are memoized per request.
      def self.root_group_actors(user)
        return [] unless user

        ::Group.root_ids_for(user.authorized_groups.select(:id)).map { |id| ::Group.actor_from_id(id) }
      end
      private_class_method :root_group_actors

      def initialize(dashboard, user)
        @constraints = dashboard.constraints
        @declared = dashboard.config.key?('constraints')
        @user = user
      end

      def satisfied?
        return unknown_constraint(:constraints, constraints) unless constraints.is_a?(Hash)
        # An absent key reads as `{}`, but the schema rejects a declared empty block.
        return unknown_constraint(:constraints, constraints) if declared && constraints.empty?

        unknown_kinds = constraints.keys - KINDS
        return unknown_constraint(:constraints, unknown_kinds) if unknown_kinds.any?

        licensed? && feature_flag_enabled? && data_available?
      end

      private

      attr_reader :constraints, :declared, :user

      # Instance-level is right for an organization-scoped dashboard, but it does not
      # discriminate on GitLab.com, where the licence maps to Ultimate for everyone.
      # See https://gitlab.com/gitlab-org/gitlab/-/work_items/630026
      # Presence is the key, not the value: `license: false` must not read as "no constraint".
      def licensed?
        return true unless constraints.key?('license')

        name = constraints['license']
        return unknown_constraint(:license, name) unless LICENSED_FEATURES.include?(name)

        ::License.feature_available?(name.to_sym)
      end

      # These flags resolve per user, directly or through the user's root
      # groups, which is why the policy condition calling this cannot use
      # `scope: :subject` -- that caches one user's answer for everyone.
      def feature_flag_enabled?
        return true unless constraints.key?('feature_flag')

        token = constraints['feature_flag']
        check = FEATURE_FLAG_CHECKS[token]
        return unknown_constraint(:feature_flag, token) unless check

        check.call(user)
      end

      # `Array()` would turn `false` or `[]` into a list that is vacuously satisfied.
      def data_available?
        return true unless constraints.key?('data')

        names = constraints['data']
        return unknown_constraint(:data, names) unless names.is_a?(Array) && names.any?

        names.all? do |name|
          check = DATA_CHECKS[name]
          check ? check.call : unknown_constraint(:data, name)
        end
      end

      # The schema rejects these values, but a dashboard is kept with its schema errors so the
      # page can show them, so a bad token reaches the policy. Loud in development, silently
      # hidden in production: the loader already reported the schema error once per load, and
      # this runs once per dashboard, per user, per request.
      def unknown_constraint(kind, value)
        raise ArgumentError, "Unknown #{kind} constraint: #{value.inspect}" if ::Gitlab.dev_or_test_env?

        false
      end
    end
  end
end
