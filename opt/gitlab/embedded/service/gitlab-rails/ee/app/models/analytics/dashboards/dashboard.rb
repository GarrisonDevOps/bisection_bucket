# frozen_string_literal: true

module Analytics
  module Dashboards
    class Dashboard
      include SchemaValidator

      attr_reader :title, :description, :schema_version, :status, :panels, :container, :grid_height,
        :config_project, :slug, :path, :user_defined, :category, :errors, :filters

      DASHBOARD_ROOT_LOCATION = '.gitlab/analytics/dashboards'
      MAX_SLUG_LENGTH = 255

      VALUE_STREAMS_DASHBOARD_NAME = 'value_streams_dashboard'
      AI_IMPACT_DASHBOARD_NAME = 'duo_and_sdlc_trends'
      CONTRIBUTION_DASHBOARD_NAME = 'contributions_dashboard'
      MERGE_REQUEST_ANALYTICS_DASHBOARD_NAME = 'merge_request_analytics'
      PROJECT_VALUE_STREAMS_DASHBOARD_NAME = 'project_value_streams_dashboard'
      SCHEMA_PATH = 'ee/app/validators/json_schemas/analytics_dashboard_legacy.json'

      def self.for(container:, user:)
        config_project = configuration_project_for(container)

        dashboards = builtin_dashboards(container, config_project, user)
        dashboards.concat(customized_dashboards(container, config_project)) if config_project

        dashboards.compact
      end

      # Reads one dashboard folder instead of listing every dashboard; the result
      # is the same as `for(...).find { |dashboard| dashboard.slug == slug }`.
      def self.find_by_slug(container:, user:, slug:)
        config_project = configuration_project_for(container)

        found = builtin_dashboards(container, config_project, user).find { |dashboard| dashboard&.slug == slug }
        return found if found
        return unless config_project && custom_dashboard_slug?(slug)

        config_data = ConfigCache.blob_data_at(config_project, dashboard_config_path(slug))
        return unless config_data

        from_config_data(container, config_project, slug, config_data)
      end

      def self.configuration_project_for(container)
        unless container.is_a?(Group) || container.is_a?(Project)
          raise ArgumentError,
            "A group or project must be provided. Given object is #{container.class.name} type"
        end

        container.analytics_dashboards_configuration_project ||
          container.default_dashboards_configuration_source
      end

      def self.customized_dashboards(container, config_project)
        slugs = ConfigCache.fetch(config_project, :dashboard_slugs) do
          trees = config_project.repository.tree(:head, DASHBOARD_ROOT_LOCATION)&.trees

          trees ? trees.map(&:name).reject { |name| name == 'visualizations' } : []
        end

        paths = slugs.index_with { |slug| dashboard_config_path(slug) }
        configs = ConfigCache.blobs_data_at(config_project, paths.values)

        slugs.filter_map do |slug|
          config_data = configs[paths[slug]]
          next unless config_data

          from_config_data(container, config_project, slug, config_data)
        end
      end

      def self.dashboard_config_path(slug)
        "#{DASHBOARD_ROOT_LOCATION}/#{slug}/#{slug}.yaml"
      end

      # Only names that can be a folder listed under DASHBOARD_ROOT_LOCATION qualify,
      # so the lookup never reads outside it and never returns a visualization.
      def self.custom_dashboard_slug?(slug)
        slug.present? &&
          slug.length <= MAX_SLUG_LENGTH &&
          slug != 'visualizations' &&
          !slug.match?(%r{[/\\\0]}) &&
          !Gitlab::PathTraversal.path_traversal?(slug)
      end

      def self.from_config_data(container, config_project, slug, config_data)
        new(
          slug: slug,
          container: container,
          config: Gitlab::Config::Loader::Yaml.new(config_data).load_raw!,
          config_project: config_project,
          user_defined: true
        )
      end

      def self.load_yaml_dashboard_config(name, file_path)
        Gitlab::PathTraversal.check_allowed_absolute_path_and_path_traversal!(name, [])

        Gitlab::Config::Loader::Yaml.new(
          File.read(Rails.root.join(file_path, "#{name}.yaml"))
        ).load_raw!
      end

      def self.value_stream_dashboard(container, config_project)
        return unless container.value_streams_dashboard_available?

        config_file_name = container.is_a?(Group) ? VALUE_STREAMS_DASHBOARD_NAME : PROJECT_VALUE_STREAMS_DASHBOARD_NAME

        config =
          load_yaml_dashboard_config(
            config_file_name,
            'ee/lib/gitlab/analytics/value_stream_dashboard/dashboards'
          )

        new(
          slug: VALUE_STREAMS_DASHBOARD_NAME,
          container: container,
          config: config,
          config_project: config_project,
          user_defined: false
        )
      end

      def self.ai_impact_dashboard(container, config_project, user)
        return unless container.ai_impact_dashboard_available_for?(user)
        # Explore serves its own copy, so listing this one as well would keep users on the
        # page we are moving them off.
        return if ::Feature.enabled?(:explore_analytics_dashboards, user)

        config = load_yaml_dashboard_config('dashboard', 'ee/lib/gitlab/analytics/ai_impact_dashboard')

        new(
          slug: AI_IMPACT_DASHBOARD_NAME,
          container: container,
          config: config,
          config_project: config_project,
          user_defined: false
        )
      end

      def self.contributions_dashboard(container, config_project)
        return unless container.contributions_dashboard_available?

        config = load_yaml_dashboard_config('dashboard', 'ee/lib/gitlab/analytics/contributions_dashboard')

        new(
          slug: CONTRIBUTION_DASHBOARD_NAME,
          container: container,
          config: config,
          config_project: config_project,
          user_defined: false
        )
      end

      def self.dora_metrics_dashboard(container, config_project)
        config = load_yaml_dashboard_config('dashboard', 'ee/lib/gitlab/analytics/dora_metrics')

        new(
          slug: 'dora_metrics',
          container: container,
          config: config,
          config_project: config_project,
          user_defined: false
        )
      end

      def self.merge_request_analytics_dashboard(container, config_project, user)
        return unless container.merge_request_analytics_enabled?(user)

        config = load_yaml_dashboard_config('dashboard', 'ee/lib/gitlab/analytics/merge_requests/dashboards')

        new(
          slug: MERGE_REQUEST_ANALYTICS_DASHBOARD_NAME,
          container: container,
          config: config,
          config_project: config_project,
          user_defined: false
        )
      end

      def self.builtin_dashboards(container, config_project, user)
        builtin = []

        builtin << value_stream_dashboard(container, config_project)
        builtin << ai_impact_dashboard(container, config_project, user)
        builtin << contributions_dashboard(container, config_project)
        builtin << dora_metrics_dashboard(container, config_project) if container.dora_metrics_dashboard_enabled?(user)
        builtin << merge_request_analytics_dashboard(container, config_project, user)

        builtin.flatten
      end

      private_class_method :configuration_project_for, :customized_dashboards, :dashboard_config_path,
        :custom_dashboard_slug?, :from_config_data

      def initialize(**args)
        @container = args[:container]
        @config_project = args[:config_project]
        @slug = args[:slug]
        @user_defined = args[:user_defined]
        @category = 'analytics'

        @yaml_definition = args[:config]
        @title = yaml_definition['title']
        @description = yaml_definition['description']
        @schema_version = yaml_definition['version']
        @status = yaml_definition['status']

        @errors = schema_errors_for(@yaml_definition)
        return if @errors.present?

        # Descriptive fields are kept for an invalid definition so it can still be
        # identified in the UI alongside its errors. The rest cannot be built safely.
        @grid_height = yaml_definition['gridHeight']
        @filters = yaml_definition['filters']
        @panels = Panel.from_data(yaml_definition['panels'], config_project, container)
      end

      def ==(other)
        slug == other.slug
      end

      private

      attr_reader :yaml_definition
    end
  end
end
