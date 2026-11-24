# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level (ScanProfileType)
      class SecretDetectionConfigurationType < BaseObject
        graphql_name 'SecretDetectionConfiguration'
        description 'Configuration for a secret detection scan profile.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :secure_analyzers_prefix, GraphQL::Types::String,
          null: true,
          description: 'Prefix for the container registry from which the analyzer image is pulled.'

        field :image_suffix, ::Types::Security::ScanProfiles::ImageSuffixEnum,
          null: true,
          description: 'Suffix appended to the analyzer image name.'

        field :historic_scan, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates whether to scan the full Git history instead of only the current state.'

        field :log_options, GraphQL::Types::String,
          null: true,
          description: 'Options passed to git log to control the commit range scanned.'

        field :excluded_paths, [GraphQL::Types::String],
          null: true,
          description: 'Glob paths excluded from the scan.'

        field :ruleset_git_reference, GraphQL::Types::String,
          null: true,
          description: 'Git reference of the remote ruleset configuration to use.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
