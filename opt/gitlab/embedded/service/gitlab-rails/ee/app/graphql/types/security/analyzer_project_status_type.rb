# frozen_string_literal: true

module Types
  module Security
    class AnalyzerProjectStatusType < BaseObject
      graphql_name 'AnalyzerProjectStatusType'
      description 'Analyzer status (success/fail) for projects'
      authorize :read_security_inventory

      field :project_id,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Project ID.'

      field :analyzer_type,
        type: AnalyzerTypeForStatusEnum,
        null: false,
        description: 'Analyzer type.'

      field :status,
        type: AnalyzerStatusEnum,
        null: false,
        description: 'Analyzer status.'

      field :last_call,
        type: Types::TimeType,
        null: false,
        description: 'Last time analyzer was called.'

      field :build_id,
        type: ::Types::GlobalIDType[::CommitStatus],
        null: true,
        description: 'Build ID.'

      field :updated_at,
        type: GraphQL::Types::ISO8601DateTime,
        null: false,
        description: 'Timestamp of when the status was last updated.'

      field :source,
        type: AnalyzerSourceEnum,
        null: true,
        experiment: { milestone: '19.0' },
        description: 'Source of the build associated with the analyzer status.'

      def source
        return unless object.build_id

        named_sources = AnalyzerSourceEnum.values.values.map(&:value).to_set
        BatchLoader::GraphQL.for(object.build_id).batch(default_value: nil,
          key: :analyzer_status_build_source) do |build_ids, loader|
          ::Ci::BuildSource.for_build_id(build_ids).each do |build_source|
            mapped = named_sources.include?(build_source.source) ? build_source.source : 'yml'
            loader.call(build_source.build_id, mapped)
          end
        end
      end
    end
  end
end
