# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyComparisonPipelineType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
      graphql_name 'PolicyComparisonPipeline'
      description 'Represents the source and target pipelines used for comparison in the policy evaluation.'

      field :report_type,
        type: ApprovalReportTypeEnum,
        null: false,
        description: 'Represents the report_type for which the pipeline IDs were evaluated.'

      field :source,
        type: [Types::GlobalIDType[::Ci::Pipeline]],
        null: true,
        description: 'Represents the list of pipeline GIDs for the source branch.'

      field :target,
        type: [Types::GlobalIDType[::Ci::Pipeline]],
        null: true,
        description: 'Represents the list of pipeline GIDs for the target branch.'
    end
  end
end
