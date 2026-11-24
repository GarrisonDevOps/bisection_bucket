# frozen_string_literal: true

module Analytics
  module Dashboards
    class Visualization
      include SchemaValidator

      attr_reader :type, :container, :data, :options, :config, :slug, :errors

      VISUALIZATIONS_ROOT_LOCATION = '.gitlab/analytics/dashboards/visualizations'
      SCHEMA_PATH = 'ee/app/validators/json_schemas/analytics_visualization_legacy.json'

      DORA_METRICS_VISUALIZATIONS_PATH = 'ee/lib/gitlab/analytics/dora_metrics/visualizations'
      DORA_METRICS_VISUALIZATIONS = %w[
        deployment_frequency_average
        time_to_restore_service_median
        lead_time_for_changes_median
        change_failure_rate
        deployment_frequency_over_time
        change_failure_rate_over_time
        time_to_restore_service_over_time
        lead_time_for_changes_over_time
      ].freeze

      VALUE_STREAM_DASHBOARD_PATH = 'ee/lib/gitlab/analytics/value_stream_dashboard/visualizations'
      VALUE_STREAM_DASHBOARD_VISUALIZATIONS = %w[
        dora_chart
        vsd_lifecycle_metrics_table
        vsd_dora_metrics_table
        vsd_security_metrics_table
        usage_overview
        dora_performers_score
        dora_projects_comparison
        namespace_metadata
        groups_count
        users_count
        projects_count
        issues_count
        merge_requests_count
        pipelines_count
      ].freeze

      AI_IMPACT_DASHBOARD_PATH = 'ee/lib/gitlab/analytics/ai_impact_dashboard/visualizations'
      AI_IMPACT_DASHBOARD_VISUALIZATIONS = %w[
        ai_impact_table
        ai_impact_lifecycle_metrics_table
        ai_impact_ai_metrics_table
        duo_power_users_count_over_time
        pipeline_metrics_table
        code_suggestions_acceptance_by_language_chart
        duo_flow_metrics_table
        duo_flows_by_user
        duo_feature_usage_table
        code_generation_volume_trends_chart
        duo_code_review_usage_by_user
        duo_code_suggestions_by_user
        duo_rca_usage_by_user
        duo_total_event_count_by_user
        code_review_requests_by_role_chart
        code_suggestions_acceptance_by_ide_chart
        code_review_comments_sentiment_over_time_chart
        duo_agent_chat_sessions_over_time
        duo_users_count_over_time
        duo_agent_platform_agent_flows_users_count_over_time
        finished_pipelines_using_dap_over_time_chart
        duo_pipelines_rate_over_time
        duo_feature_user_retention_over_time
      ].freeze

      CONTRIBUTIONS_DASHBOARD_PATH = 'ee/lib/gitlab/analytics/contributions_dashboard/visualizations'
      CONTRIBUTIONS_DASHBOARD_VISUALIZATIONS = %w[
        pushes
        merge_requests
        issues
        contributions_by_user
      ].freeze

      VISUALIZATIONS_FOR_GROUP_ONLY = %w[
        dora_performers_score
        dora_projects_comparison
        groups_count
        users_count
        projects_count
      ].freeze

      MERGE_REQUESTS_VISUALIZATIONS_PATH = 'ee/lib/gitlab/analytics/merge_requests/visualizations'
      MERGE_REQUESTS_VISUALIZATIONS = %w[
        mean_time_to_merge
        merge_requests_over_time
        merge_requests_throughput_table
      ].freeze

      def self.for(container:, user:)
        config_project =
          container.analytics_dashboards_configuration_project ||
          container.default_dashboards_configuration_source

        visualizations = []
        visualizations << custom_visualizations(container, config_project)
        visualizations << builtin_visualizations(container, user)

        visualizations.flatten
      end

      def self.custom_visualizations(container, config_project)
        return [] unless config_project

        entries = ConfigCache.fetch(config_project, :visualization_entries) do
          trees = config_project.repository.tree(:head, VISUALIZATIONS_ROOT_LOCATION)

          trees ? trees.entries.map { |entry| [entry.name, entry.path] } : []
        end

        configs = ConfigCache.blobs_data_at(config_project, entries.map(&:last))

        entries.map do |name, path|
          new(container: container, config: configs[path], slug: File.basename(name, File.extname(name)))
        end
      end

      def self.from_file(filename:, config_project:, container:)
        return unless filename

        # Resolve built-in visualizations from the bundled files first, falling back to the project
        # repository only for custom (non-built-in) visualizations. This avoids a Gitaly blob lookup
        # per built-in panel, which previously caused an N+1 when loading built-in dashboards.
        content = load_builtin_visualization_data(filename: filename)
        content ||= load_project_visualization_data(filename: filename, project: config_project)

        if content
          new(container: container, config: content, slug: filename)
        else
          new(container: container, config: nil, slug: filename,
            init_error: "Visualization file #{filename}.yaml not found")
        end
      end

      def self.from_data(data:, container:)
        return unless data

        slug = if data.key?('slug')
                 data['slug']
               else
                 SecureRandom.alphanumeric(10)
               end

        new(container: container, config: YAML.safe_dump(data), slug: slug)
      end

      def self.skip_for_project_namespace?(name)
        VISUALIZATIONS_FOR_GROUP_ONLY.include?(name)
      end

      def self.value_stream_dashboard_visualizations(container, is_project = false)
        unsafe_load_builtin_visualizations(VALUE_STREAM_DASHBOARD_VISUALIZATIONS,
          VALUE_STREAM_DASHBOARD_PATH, container, is_project)
      end

      def self.ai_impact_dashboard_visualizations(container, is_project = false)
        unsafe_load_builtin_visualizations(AI_IMPACT_DASHBOARD_VISUALIZATIONS, AI_IMPACT_DASHBOARD_PATH, container,
          is_project)
      end

      def self.dora_metrics_visualizations(container, is_project = false)
        unsafe_load_builtin_visualizations(DORA_METRICS_VISUALIZATIONS, DORA_METRICS_VISUALIZATIONS_PATH, container,
          is_project)
      end

      def self.merge_requests_visualizations(container)
        unsafe_load_builtin_visualizations(MERGE_REQUESTS_VISUALIZATIONS, MERGE_REQUESTS_VISUALIZATIONS_PATH, container,
          true)
      end

      def self.builtin_visualizations(container, user)
        is_project = container.is_a?(Project)

        visualizations = []

        if container.value_streams_dashboard_available?
          visualizations << value_stream_dashboard_visualizations(container, is_project)
        end

        if container.value_streams_dashboard_available? && container.dora_metrics_dashboard_enabled?(user)
          visualizations << dora_metrics_visualizations(container, is_project)
        end

        if container.ai_impact_dashboard_available_for?(user)
          visualizations << ai_impact_dashboard_visualizations(container, is_project)
        end

        visualizations << merge_requests_visualizations(container) if container.merge_request_analytics_enabled?(user)

        visualizations.flatten
      end

      def initialize(container:, config:, slug:, init_error: nil)
        raise ArgumentError, 'container cannot be nil' if container.nil?

        if init_error
          initialize_with_error(container, init_error, slug)
          return
        end

        begin
          @config = YAML.safe_load(config)
          @type = @config['type']
          @options = @config['options']
          @data = @config['data']
        rescue Psych::Exception => e
          @errors = [e.message]
        end
        @container = container
        @slug = slug&.parameterize
        @errors = schema_errors_for(@config)
      end

      def initialize_with_error(container, init_error, slug)
        raise ArgumentError, 'container cannot be nil' if container.nil?

        @container = container
        @options = {}
        @type = 'unknown'
        @data = {}
        @errors = [init_error]
        @slug = slug&.parameterize
      end

      class << self
        private

        def get_path_for_visualization(data)
          if VALUE_STREAM_DASHBOARD_VISUALIZATIONS.include?(data)
            VALUE_STREAM_DASHBOARD_PATH
          elsif AI_IMPACT_DASHBOARD_VISUALIZATIONS.include?(data)
            AI_IMPACT_DASHBOARD_PATH
          elsif CONTRIBUTIONS_DASHBOARD_VISUALIZATIONS.include?(data)
            CONTRIBUTIONS_DASHBOARD_PATH
          elsif DORA_METRICS_VISUALIZATIONS.include?(data)
            DORA_METRICS_VISUALIZATIONS_PATH
          elsif MERGE_REQUESTS_VISUALIZATIONS.include?(data)
            MERGE_REQUESTS_VISUALIZATIONS_PATH
          end
        end

        def visualization_config_path(data)
          "#{Dashboard::DASHBOARD_ROOT_LOCATION}/visualizations/#{data}.yaml"
        end

        def load_project_visualization_data(filename:, project:)
          return unless project

          ConfigCache.blob_data_at(project, visualization_config_path(filename))
        end

        def load_builtin_visualization_data(filename:)
          Gitlab::PathTraversal.check_path_traversal!(filename)

          path = get_path_for_visualization(filename)
          return unless path

          file = Rails.root.join(path, "#{filename}.yaml")

          Gitlab::PathTraversal.check_allowed_absolute_path!(
            file.to_s, [Rails.root.join(path).to_s]
          )

          File.read(file)
        rescue Errno::ENOENT
          nil
        end

        def unsafe_load_builtin_visualizations(visualization_names, directory, container, is_project)
          visualization_names.filter_map do |name|
            next if is_project && skip_for_project_namespace?(name)

            config = File.read(Rails.root.join(directory, "#{name}.yaml"))

            new(container: container, config: config, slug: name)
          end
        end
      end
    end
  end
end
