# frozen_string_literal: true

module Types
  module Security
    class AnalyzerTypeForStatusEnum < AnalyzerTypeEnum
      graphql_name 'AnalyzerTypeForStatus'
      description 'Analyzer types that can appear in project and group analyzer statuses.'

      value 'DEPENDENCY_SCANNING_POST_PROCESSING',
        value: 'dependency_scanning_post_processing',
        description: 'Dependency scanning post-processing.'
    end
  end
end
