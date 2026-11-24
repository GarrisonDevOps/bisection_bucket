# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level (ScanProfileType)
      class DependencyScanningConfigurationType < BaseObject
        graphql_name 'DependencyScanningConfiguration'
        description 'Configuration for a dependency scanning scan profile.'

        authorize_granular_token skip_reason: :parent_authorizes

        # rubocop:disable GraphQL/ExtractType -- each field maps to an independent CI variable
        field :secure_analyzers_prefix, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Prefix for the container registry from which the analyzer image is pulled.'

        field :additional_ca_cert_bundle, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: "CA certificate bundle to trust. The bundle is added to the system's certificates " \
            'and used by other tools during the scan.'

        field :secure_log_level, ::Types::Security::ScanProfiles::SecureLogLevelEnum,
          null: true, experiment: { milestone: '19.5' },
          description: 'Logging level used by the analyzer.'

        field :excluded_paths, [GraphQL::Types::String],
          null: true, experiment: { milestone: '19.5' },
          description: 'Glob paths excluded from the scan.'

        field :include_dev_dependencies, GraphQL::Types::Boolean,
          null: true, experiment: { milestone: '19.5' },
          description: 'Whether development and test dependencies are included when scanning a supported file.'

        field :max_depth, GraphQL::Types::Int,
          null: true, experiment: { milestone: '19.5' },
          description: 'Specifies the directory depth the analyzer should scan. ' \
            'A value of -1 scans all directories.'

        field :pip_dependency_path, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Path to install Python packages for analysis.'

        field :static_reachability_enabled, GraphQL::Types::Boolean,
          null: true, experiment: { milestone: '19.5' },
          description: 'Whether static reachability is enabled.'

        field :enable_manifest_fallback, GraphQL::Types::Boolean,
          null: true, experiment: { milestone: '19.5' },
          description: 'Whether manifest fallback for dependency scanning is enabled.'

        field :pipcompile_lockfile_file_name_pattern, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Custom pipcompile lockfile file name pattern to use when analyzing. ' \
            'The pattern matches file names only, not directory paths.'

        field :pip_manifest_file_name_pattern, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Custom pip manifest file name pattern to use for dependency resolution and ' \
            'manifest scanning. The pattern matches file names only, not directory paths.'

        field :enable_vulnerability_scan, GraphQL::Types::Boolean,
          null: true, experiment: { milestone: '19.5' },
          description: 'Whether the vulnerability analysis of generated SBOMs is enabled.'

        field :api_timeout, GraphQL::Types::Int,
          null: true, experiment: { milestone: '19.5' },
          description: 'Vulnerability scanning API request timeout in seconds.'

        field :api_scan_download_delay, GraphQL::Types::Int,
          null: true, experiment: { milestone: '19.5' },
          description: 'Vulnerability scanning API initial delay in seconds before downloading scan results.'

        field :maven_dependency_plugin_version, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Version of maven-dependency-plugin used during resolution.'

        field :maven_args, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Additional arguments passed to Maven during dependency resolution.'

        field :gradle_cli_opts, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Additional command-line options passed to Gradle during dependency resolution.'

        field :disabled_resolution_jobs, [::Types::Security::ScanProfiles::DependencyResolutionJobEnum],
          null: true, experiment: { milestone: '19.5' },
          description: 'Resolution jobs that are disabled.'

        field :maven_resolution_image, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Image used by the Maven dependency resolution job.'

        field :gradle_resolution_image, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Image used by the Gradle dependency resolution job.'

        field :python_resolution_image, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Image used by the Python dependency resolution job.'

        field :pip_index_url, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.5' },
          description: 'Base URL of the Python Package Index.'

        field :pip_extra_index_url, [GraphQL::Types::String],
          null: true, experiment: { milestone: '19.5' },
          description: 'Additional URLs of Python package indexes used in addition to pipIndexUrl.'

        field :search_ignore_hidden_dirs, GraphQL::Types::Boolean,
          null: true, experiment: { milestone: '19.5' },
          description: 'Whether hidden directories are ignored when searching for supported files.'

        field :analyzer_image_version, GraphQL::Types::String,
          null: true, experiment: { milestone: '19.6' },
          description: 'Version tag of the dependency scanning analyzer image.'
        # rubocop:enable GraphQL/ExtractType
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
