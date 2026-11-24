# frozen_string_literal: true

module Types
  module Security
    class AnalyzerStatusEnum < Types::BaseEnum
      graphql_name 'AnalyzerStatusEnum'
      description 'Enum for types of analyzers '

      value 'SUCCESS', value: 'success', description: "Last analyzer execution finished successfully."
      value 'FAILED', value: 'failed', description: "Last analyzer execution failed."
      value 'NOT_CONFIGURED', value: 'not_configured', description: "Analyzer is not configured."
      value 'STALE', value: 'stale', description: "Analyzer is configured, but has not run in any recent pipelines."
    end
  end
end
