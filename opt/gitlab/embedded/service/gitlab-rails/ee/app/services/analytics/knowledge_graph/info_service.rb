# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class InfoService
      include ActionView::Helpers::NumberHelper
      include ActionView::Helpers::DateHelper

      FEATURE_FLAG_PREFIXES = %w[knowledge_graph orbit_ gkg_].freeze
      DEFAULT_GRPC_ENDPOINT = GrpcClient::DEFAULT_GRPC_ENDPOINT

      def self.execute(...)
        new(...).execute
      end

      def initialize(logger:, options: {})
        @logger = logger
        @entries = []
        @options = options
      end

      def execute
        display_settings_section
        display_service_health_section
        display_indexing_status_section
        display_feature_flags_sections

        return unless options[:extended_mode]

        display_enabled_namespace_details
      end

      private

      attr_reader :logger, :entries, :options

      def display_settings_section
        log_header("Orbit / Knowledge Graph")
        log("GitLab version", value: Gitlab.version_info)
        log("Deployment", value: deployment_type)
        log("knowledge_graph.enabled", value: knowledge_graph_enabled?)
        log("gRPC endpoint", value: grpc_endpoint_display)
        log("License :orbit available", value: orbit_license_available?)

        unless Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          log("Orbit instance access", value: instance_orbit_access_state)
        end

        Settings.all_settings.each do |setting_name, config|
          log(config[:label].call, value: Gitlab::CurrentSettings[setting_name])
        end
        display_entries
      end

      # rubocop:disable Gitlab/AvoidGitlabDedicatedInstanceChecks -- diagnostic display, not a feature gate
      def deployment_type
        if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          'SaaS'
        elsif ::Gitlab::CurrentSettings.gitlab_dedicated_instance?
          'Dedicated'
        else
          'Self-managed'
        end
      end
      # rubocop:enable Gitlab/AvoidGitlabDedicatedInstanceChecks

      def knowledge_graph_enabled?
        Gitlab.config.knowledge_graph['enabled']
      rescue Gitlab::Configs::MissingConfig
        false
      end

      def grpc_endpoint_display
        endpoint = GrpcClient.configured_endpoint
        if endpoint == DEFAULT_GRPC_ENDPOINT
          "#{endpoint} #{Rainbow('(default - not explicitly configured)').yellow}"
        else
          endpoint
        end
      end

      def orbit_license_available?
        if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          '(per-namespace on SaaS)'
        else
          License.feature_available?(:orbit)
        end
      rescue StandardError
        false
      end

      def instance_orbit_access_state
        ::Analytics::Orbit::Billing.instance_account.access(group: nil, current_user: nil).state
      rescue StandardError
        'unknown'
      end

      def display_service_health_section
        log_header("Service health")
        log("gRPC endpoint", value: GrpcClient.configured_endpoint)

        user_value = ENV['ORBIT_INFO_USER']
        if user_value.present?
          probe_cluster_health(user_value)
        else
          log("Cluster health", value: Rainbow('skipped (set ORBIT_INFO_USER to probe GKG cluster health)').yellow)
        end

        display_entries
      end

      def probe_cluster_health(user_value)
        user = resolve_user(user_value)

        unless user
          log("Cluster health",
            value: Rainbow("user '#{user_value}' not found - cannot probe").red)
          return
        end

        result = fetch_cluster_health(user)
        render_cluster_health(result)
      end

      # Rescue the three operational failure modes that can occur before or
      # during the gRPC call: AuthorizationError (JWT secret missing/unreadable),
      # ConnectionError (endpoint unreachable at channel level), and
      # GRPC::BadStatus (RPC-level failure, normally caught inside the client
      # but included here as a safety net). Programming errors like
      # ArgumentError are intentionally not rescued.
      def fetch_cluster_health(user)
        client = GrpcClient.new
        # An explicit source_type is required: GKG rejects JWTs with a null
        # source_type claim. REST is the appropriate classification for a
        # server-side diagnostic invoked via rake.
        context = RequestContext.new(source_type: SourceType::REST)
        client.get_cluster_health(user: user, request_context: context)
      rescue GrpcClient::AuthorizationError, GrpcClient::ConnectionError, GRPC::BadStatus => e
        { status: 'unknown', error: e.message }
      end

      def render_cluster_health(result)
        if result[:error]
          log("Cluster health status", value: Rainbow(result[:status]).red)
          log("Cluster health error", value: Rainbow(result[:error]).red)
          return
        end

        status_color = result[:status] == 'healthy' ? :green : :yellow
        log("Cluster health status", value: Rainbow(result[:status]).color(status_color))
        log("Cluster health version", value: result[:version]) if result[:version].present?
        log("Cluster health timestamp", value: result[:timestamp]) if result[:timestamp].present?

        return unless result[:components].present?

        result[:components].each do |component|
          component_status = component[:status] || 'unknown'
          component_color = component_status == 'healthy' ? :green : :yellow
          log("  #{component[:name]}", value: Rainbow(component_status).color(component_color))
        end
      end

      def resolve_user(value)
        if value.match?(/\A\d+\z/)
          User.find_by_id(value)
        else
          User.find_by_username(value)
        end
      end

      def display_indexing_status_section
        log_header("Indexing status")
        log("Group count (top-level)", value: Group.top_level.count)
        log("EnabledNamespace count", value: EnabledNamespace.count)
        log("ExcludedNamespace count", value: ExcludedNamespace.count)
        # rubocop:disable CodeReuse/ActiveRecord -- time-scoped count for diagnostic display
        log("CodeIndexingTask count (last 24h)", value: CodeIndexingTask.where(created_at: 24.hours.ago..).count)
        # rubocop:enable CodeReuse/ActiveRecord
        display_entries
      end

      def display_feature_flags_sections
        log_header("Feature Flags (Non-Default Values)")
        log_custom_feature_flags
        display_entries

        log_header("Feature Flags (Default Values)")
        log_default_feature_flags
        display_entries
      end

      def orbit_flag?(name)
        FEATURE_FLAG_PREFIXES.any? { |prefix| name.to_s.start_with?(prefix) }
      end

      def log_custom_feature_flags
        persisted_flags = Feature.persisted_names.select { |name| orbit_flag?(name) }

        if persisted_flags.empty?
          log("Feature flags", value: Rainbow('none').yellow)
          return
        end

        flag_states = {}
        persisted_flags.each do |flag|
          flag_states[flag] = feature_flag_state(flag.to_sym)
        end

        flag_states.sort.each do |flag, state|
          log("- #{flag}", value: state)
        end
      end

      def log_default_feature_flags
        all_flags = Feature::Definition.definitions.keys
        orbit_flags = all_flags.select { |name| orbit_flag?(name) }

        default_flags = orbit_flags.reject { |flag| Feature.persisted_name?(flag.to_s) }

        if default_flags.empty?
          log("Feature flags", value: Rainbow('none').yellow)
          return
        end

        flag_states = {}
        default_flags.each do |flag|
          flag_states[flag] = feature_flag_state(flag)
        end

        flag_states.sort_by { |k, _| k.to_s }.each do |flag, state|
          log("- #{flag}", value: state)
        end
      end

      # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- iterating over discovered flags by prefix
      def feature_flag_state(flag)
        return Rainbow('no definition').yellow unless Feature::Definition.has_definition?(flag)

        enabled = Feature.enabled?(flag, Feature.current_request)
        state_text = enabled ? 'enabled' : 'disabled'
        state_color = enabled ? :green : :red
        Rainbow(state_text).color(state_color)
      end
      # rubocop:enable Gitlab/FeatureFlagKeyDynamic

      def display_enabled_namespace_details
        log_header("Enabled Namespace Details")

        # rubocop:disable CodeReuse/ActiveRecord -- eager-loading for diagnostic display
        namespaces = EnabledNamespace.recent.with_limit(20).includes(:namespace)
        # rubocop:enable CodeReuse/ActiveRecord
        if namespaces.empty?
          log("Enabled namespaces", value: Rainbow('(none)').yellow)
          display_entries
          return
        end

        namespaces.each do |en|
          namespace = en.namespace
          path = namespace&.full_path || Rainbow('(unknown)').yellow
          log("Namespace #{en.root_namespace_id}", value: path)
          log("  Created at", value: en.created_at)
        end

        display_entries
      end

      def format_value(value)
        case value
        when TrueClass
          Rainbow('yes').green
        when FalseClass
          'no'
        when ActiveSupport::TimeWithZone, Time
          utc_time = value.utc
          relative_time = time_ago_in_words(utc_time)
          "#{utc_time} (#{relative_time} ago)"
        when NilClass
          Rainbow('(never)').yellow
        else
          value.to_s
        end
      end

      def log_header(message)
        display_entries
        logger.info("\n#{Rainbow(message).bright.yellow.underline}")
        @entries = []
      end

      def log(key, value: nil, nested: nil)
        entries << {
          key: key,
          value: value,
          nested: nested
        }
      end

      def display_entries
        return if entries.empty?

        max_length = entries.map { |entry| entry[:key].length }.max
        padding = max_length + 2

        entries.each do |entry|
          key_with_padding = "#{entry[:key]}:#{' ' * (padding - entry[:key].length)}"

          if entry[:nested]
            if entry[:nested].empty?
              logger.info("#{key_with_padding}#{Rainbow('(none)').yellow}")
            else
              logger.info("#{key_with_padding}#{entry[:value]}")
              display_nested_value(entry[:nested])
            end
          else
            formatted_value = format_value(entry[:value])
            logger.info("#{key_with_padding}#{formatted_value}")
          end
        end
        @entries = []
      end

      def display_nested_value(value, indent = 2)
        value.sort.each do |k, v|
          colored_value = case k.to_sym
                          when :failed
                            Rainbow(v).red.bright
                          when :done, :ready, :healthy
                            Rainbow(v).green
                          else
                            v
                          end

          logger.info("#{' ' * indent}- #{k}: #{colored_value}")
        end
      end
    end
  end
end
