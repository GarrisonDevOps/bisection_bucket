# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class SecretDetectionConfigurationInputType < BaseInputObject
        graphql_name 'SecurityScanProfileSecretDetectionConfigurationInput'
        description 'Configuration for a secret detection scan profile.'

        argument :secure_analyzers_prefix, GraphQL::Types::String,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Prefix for the container registry from which the analyzer image is pulled.'

        argument :image_suffix, ::Types::Security::ScanProfiles::ImageSuffixEnum,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Suffix appended to the analyzer image name.'

        argument :historic_scan, GraphQL::Types::Boolean,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Whether to scan the full git history instead of only the current state.'

        argument :log_options, GraphQL::Types::String,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Options passed to git log to control the commit range scanned.'

        argument :excluded_paths, [GraphQL::Types::String],
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Glob paths excluded from the scan.'

        argument :ruleset_git_reference, GraphQL::Types::String,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Git reference of the remote ruleset configuration to use.'
      end
    end
  end
end
