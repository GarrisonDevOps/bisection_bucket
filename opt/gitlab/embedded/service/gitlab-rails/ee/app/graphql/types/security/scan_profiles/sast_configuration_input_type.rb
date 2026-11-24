# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class SastConfigurationInputType < BaseInputObject
        graphql_name 'SecurityScanProfileSastConfigurationInput'
        description 'Configuration for a SAST scan profile.'

        argument :secure_analyzers_prefix, GraphQL::Types::String,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Prefix for the container registry from which the analyzer image is pulled.'

        argument :image_suffix, ::Types::Security::ScanProfiles::ImageSuffixEnum,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Suffix appended to the analyzer image name.'

        argument :analyzer_image_tag, GraphQL::Types::String,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Tag of the analyzer image to use. Warning: Setting this value ' \
            'overrides the pinned image tag for all SAST analyzers, which can cause ' \
            'analyzer failures if they require specific versions.'

        argument :excluded_analyzers, [GraphQL::Types::String],
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Analyzers excluded from the scan.'

        argument :excluded_paths, [GraphQL::Types::String],
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Glob paths excluded from the scan.'

        argument :advanced_sast_partial_scan, ::Types::Security::ScanProfiles::AdvancedSastPartialScanEnum,
          required: false,
          experiment: { milestone: '19.4' },
          description: "Controls GitLab Advanced SAST diff-based scanning. " \
            "Use 'differential' to enable, 'false' to disable."

        argument :gitlab_adv_sast_incr_scan, GraphQL::Types::Boolean,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Whether GitLab Advanced SAST incremental scanning is enabled.'
      end
    end
  end
end
