# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class DependencyScanningConfigurationInputType < BaseInputObject
        graphql_name 'SecurityScanProfileDependencyScanningConfigurationInput'
        description 'Configuration for a dependency scanning scan profile.'

        argument :secure_analyzers_prefix, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Prefix for the container registry from which the analyzer image is pulled.'

        argument :additional_ca_cert_bundle, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: "CA certificate bundle to trust. The bundle is added to the system's certificates " \
            'and used by other tools during the scan.'

        argument :secure_log_level, ::Types::Security::ScanProfiles::SecureLogLevelEnum,
          required: false, experiment: { milestone: '19.5' },
          description: 'Logging level used by the analyzer.'

        argument :excluded_paths, [GraphQL::Types::String],
          required: false, experiment: { milestone: '19.5' },
          description: 'Glob paths excluded from the scan.'

        argument :include_dev_dependencies, GraphQL::Types::Boolean,
          required: false, experiment: { milestone: '19.5' },
          description: 'Include development and test dependencies when scanning a supported file.'

        argument :max_depth, GraphQL::Types::Int,
          required: false, experiment: { milestone: '19.5' },
          validates: { numericality: { greater_than_or_equal_to: -1 }, allow_null: true },
          description: 'Specifies the directory depth the analyzer should scan. ' \
            'A value of -1 scans all directories.'

        argument :pip_dependency_path, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Path to install Python packages for analysis.'

        argument :static_reachability_enabled, GraphQL::Types::Boolean,
          required: false, experiment: { milestone: '19.5' },
          description: 'Enable static reachability.'

        argument :enable_manifest_fallback, GraphQL::Types::Boolean,
          required: false, experiment: { milestone: '19.5' },
          description: 'Enable manifest fallback for dependency scanning.'

        argument :pipcompile_lockfile_file_name_pattern, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Custom pipcompile lockfile file name pattern to use when analyzing. ' \
            'The pattern matches file names only, not directory paths.'

        argument :pip_manifest_file_name_pattern, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Custom pip manifest file name pattern to use for dependency resolution and ' \
            'manifest scanning. The pattern matches file names only, not directory paths.'

        argument :enable_vulnerability_scan, GraphQL::Types::Boolean,
          required: false, experiment: { milestone: '19.5' },
          description: 'Enable the vulnerability analysis of generated SBOMs.'

        argument :api_timeout, GraphQL::Types::Int,
          required: false, experiment: { milestone: '19.5' },
          validates: { numericality: { within: 5..300 }, allow_null: true },
          description: 'Vulnerability scanning API request timeout in seconds, from 5 to 300.'

        argument :api_scan_download_delay, GraphQL::Types::Int,
          required: false, experiment: { milestone: '19.5' },
          validates: { numericality: { within: 1..120 }, allow_null: true },
          description: 'Vulnerability scanning API initial delay in seconds before downloading scan results, ' \
            'from 1 to 120.'

        argument :maven_dependency_plugin_version, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Version of maven-dependency-plugin used during resolution.'

        argument :maven_args, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Additional arguments passed to Maven during dependency resolution.'

        argument :gradle_cli_opts, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Additional command-line options passed to Gradle during dependency resolution.'

        argument :disabled_resolution_jobs, [::Types::Security::ScanProfiles::DependencyResolutionJobEnum],
          required: false, experiment: { milestone: '19.5' },
          description: 'Resolution jobs to disable. By default, all available resolution jobs are enabled.'

        argument :maven_resolution_image, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Image used by the Maven dependency resolution job.'

        argument :gradle_resolution_image, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Image used by the Gradle dependency resolution job.'

        argument :python_resolution_image, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Image used by the Python dependency resolution job.'

        argument :pip_index_url, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.5' },
          description: 'Base URL of the Python Package Index.'

        argument :pip_extra_index_url, [GraphQL::Types::String],
          required: false, experiment: { milestone: '19.5' },
          description: 'Additional URLs of Python package indexes to use in addition to pipIndexUrl.'

        argument :search_ignore_hidden_dirs, GraphQL::Types::Boolean,
          required: false, experiment: { milestone: '19.5' },
          description: 'Ignore hidden directories when searching for supported files.'

        argument :analyzer_image_version, GraphQL::Types::String,
          required: false, experiment: { milestone: '19.6' },
          description: 'Version tag of the dependency scanning analyzer image.'
      end
    end
  end
end
