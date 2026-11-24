# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level (ScanProfileType)
      class SastConfigurationType < BaseObject
        graphql_name 'SastConfiguration'
        description 'Configuration for a SAST scan profile.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :secure_analyzers_prefix, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Prefix for the container registry from which the analyzer image is pulled.'

        field :image_suffix, ::Types::Security::ScanProfiles::ImageSuffixEnum,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Suffix appended to the analyzer image name.'

        field :analyzer_image_tag, GraphQL::Types::String,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Tag of the analyzer image to use.'

        # rubocop:disable GraphQL/ExtractType -- two independent fields
        field :excluded_analyzers, [GraphQL::Types::String],
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Analyzers excluded from the scan.'

        field :excluded_paths, [GraphQL::Types::String],
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Glob paths excluded from the scan.'
        # rubocop:enable GraphQL/ExtractType

        field :advanced_sast_partial_scan, ::Types::Security::ScanProfiles::AdvancedSastPartialScanEnum,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Controls GitLab Advanced SAST diff-based scanning.'

        field :gitlab_adv_sast_incr_scan, GraphQL::Types::Boolean,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Whether GitLab Advanced SAST incremental scanning is enabled.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
