# frozen_string_literal: true

module Types
  module Security
    class AnalyzerFilterInputType < Types::BaseInputObject
      graphql_name 'AnalyzerFilterInput'
      description 'Input type for filtering projects by analyzer type and status'

      argument :analyzer_type, Types::Security::AnalyzerTypeEnum,
        required: true,
        description: 'Type of analyzer to filter by.'

      argument :status, Types::Security::AnalyzerStatusEnum,
        required: true,
        description: 'Status of the analyzer to filter by.'
    end
  end
end
