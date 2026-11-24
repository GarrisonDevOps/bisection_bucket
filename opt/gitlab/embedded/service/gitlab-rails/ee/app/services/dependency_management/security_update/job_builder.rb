# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class JobBuilder
      # Builds a job configuration hash compatible with the dependency-management orchestrator.
      # See: https://gitlab.com/gitlab-org/security-products/dependency-management/orchestrator/-/blob/main/schema.json

      # Maps GitLab package manager names to orchestrator ecosystem names.
      PACKAGE_MANAGER_MAPPING = {
        'bundler' => 'bundler',
        'maven' => 'maven',
        'gradle' => 'gradle',
        'pip' => 'python',
        'pipenv' => 'python',
        'poetry' => 'python',
        'setuptools' => 'python',
        'uv' => 'uv',
        'npm' => 'npm_and_yarn',
        'yarn' => 'npm_and_yarn',
        'pnpm' => 'npm_and_yarn',
        'bun' => 'bun',
        'go' => 'go_modules',
        'cargo' => 'cargo',
        'nuget' => 'nuget',
        'pub' => 'pub',
        'swift' => 'swift'
      }.freeze

      # Ecosystems whose components GitLab stores as "group/artifact" but the
      # updater identifies as "group:artifact".
      COLON_SEPARATED_ECOSYSTEMS = %w[maven gradle].freeze

      # The orchestrator no longer defaults to blocking major version bumps (see
      # https://gitlab.com/gitlab-org/security-products/dependency-management/updater/-/merge_requests/160),
      # so the job builder sends explicit ignore-conditions derived from the
      # configured upgrade policy: the highest version bump the update may contain.
      IGNORED_UPDATE_TYPES_BY_UPGRADE_POLICY = {
        'patch' => %w[version-update:semver-minor version-update:semver-major],
        'minor' => %w[version-update:semver-major],
        'major' => []
      }.freeze

      # GitLab stores the component as "namespace/name" (see Sbom::Occurrence), but the
      # updater identifies Maven/Gradle dependencies as "group:artifact". Convert the
      # namespace/name boundary (the last slash) so the updater matches the dependency.
      def self.updater_dependency_name(ecosystem, component_name)
        return component_name unless COLON_SEPARATED_ECOSYSTEMS.include?(ecosystem)

        namespace, separator, name = component_name.rpartition('/')
        separator.empty? ? component_name : "#{namespace}:#{name}"
      end

      # @param request [DependencyManagement::SecurityUpdate::Request, DependencyManagement::SecurityUpdate::BatchRequest]
      # @param project [Project]
      # @param auto_remediation_configuration [Hash] the `auto_remediation` section of the
      #   remediation profile's effective configuration (see Security::ScanProfiles::Configuration)
      # @param credentials [Array<Hash>] dependabot registry credentials whose secret values are
      #   still `${VARIABLE}` placeholders; the orchestrator substitutes them inside the job
      def initialize(request:, project:, auto_remediation_configuration: {}, credentials: [])
        @request = request
        @project = project
        @auto_remediation_configuration = auto_remediation_configuration
        @credentials = credentials
      end

      def build
        {
          'package-manager' => package_manager,
          'source' => source_config,
          'dependencies' => updater_dependency_names,
          'cooldown' => cooldown_config,
          'ignore-conditions' => ignore_conditions,
          'credentials' => credentials.presence
        }.compact
      end

      def to_json(*_args)
        build.to_json
      end

      private

      attr_reader :request, :project, :auto_remediation_configuration, :credentials

      def package_manager
        PACKAGE_MANAGER_MAPPING.fetch(request.ecosystem, request.ecosystem)
      end

      def updater_dependency_names
        request.dependency_names.map { |name| self.class.updater_dependency_name(request.ecosystem, name) }
      end

      def source_config
        {
          'repo' => project.full_path,
          'directories' => [directory_from_filepath]
        }
      end

      def directory_from_filepath
        return '/' if request.filepath.blank?

        dir = File.dirname(request.filepath)
        dir == '.' ? '/' : "/#{dir}"
      end

      def cooldown_config
        days = auto_remediation_configuration[:cooldown]
        return unless days

        { 'default-days' => days }
      end

      def ignore_conditions
        update_types = IGNORED_UPDATE_TYPES_BY_UPGRADE_POLICY.fetch(auto_remediation_configuration[:upgrade_policy], [])
        return if update_types.empty?

        [{ 'dependency-name' => '*', 'update-types' => update_types }]
      end
    end
  end
end
