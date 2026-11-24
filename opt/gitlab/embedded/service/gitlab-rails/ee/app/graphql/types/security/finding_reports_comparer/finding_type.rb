# frozen_string_literal: true

module Types
  module Security
    module FindingReportsComparer
      # rubocop: disable Graphql/AuthorizeTypes -- Parent node applies authorization
      class FindingType < BaseObject
        graphql_name 'ComparedSecurityReportFinding'

        authorize_granular_token skip_reason: :parent_authorizes

        description 'Represents finding.'

        field :uuid,
          type: GraphQL::Types::String,
          null: true,
          description: 'UUIDv5 digest based on the vulnerability\'s report type, primary identifier, location, ' \
                       'fingerprint, project identifier.'

        field :title,
          type: GraphQL::Types::String,
          null: true,
          description: 'Title of the vulnerability finding.',
          hash_key: :name

        field :unverified,
          type: GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether the finding was detected without an identified source (untrusted input).',
          hash_key: 'unverified'

        field :description,
          type: GraphQL::Types::String,
          null: true,
          description: 'Description of the vulnerability finding.'

        field :state,
          type: VulnerabilityStateEnum,
          null: true,
          description: 'Finding status.'

        field :severity,
          type: VulnerabilitySeverityEnum,
          null: true,
          description: 'Severity of the vulnerability finding.'

        field :scanner,
          type: FindingReportsComparer::ScannerType,
          null: true,
          description: 'Compared report vulnerability scanner.',
          hash_key: "scanner"

        field :found_by_pipeline_iid,
          type: GraphQL::Types::String,
          null: true,
          description: 'IID of the pipeline.'

        field :location,
          type: VulnerabilityLocationType,
          null: true,
          experiment: { milestone: '16.3' },
          description: 'Location of the vulnerability finding.'

        field :ai_resolution_enabled,
          type: GraphQL::Types::Boolean,
          null: true,
          experiment: { milestone: '18.6' },
          description: 'Indicates whether the specific finding can be resolved with AI.'

        field :matches_auto_dismiss_policy,
          type: GraphQL::Types::Boolean,
          null: true,
          experiment: { milestone: '18.9' },
          description: 'Indicates whether the finding matches an auto-dismiss policy.'

        field :auto_severity_override,
          type: VulnerabilitySeverityEnum,
          null: true,
          experiment: { milestone: '18.11' },
          description: 'The severity that will be automatically applied after merge by a severity override policy. ' \
                       'Returns `null` if no severity override policy matches.'

        field :identifiers,
          type: [VulnerabilityIdentifierType],
          null: true,
          experiment: { milestone: '16.3' },
          description: 'Identifiers of the vulnerability finding.',
          hash_key: "identifiers"

        field :details,
          type: [VulnerabilityDetailType],
          null: false,
          experiment: { milestone: '17.6' },
          description: 'Details of the vulnerability finding.',
          resolver: Resolvers::Vulnerabilities::DetailsResolver

        def found_by_pipeline_iid
          object.dig('found_by_pipeline', 'iid')
        end

        def location
          object['location'].merge(
            report_type: object['report_type'],
            blob_path: object['blob_path']
          )
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
