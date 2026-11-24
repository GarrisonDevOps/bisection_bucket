# frozen_string_literal: true

module Types
  module Security
    class PipelineSecurityReportFindingSortEnum < BaseEnum
      graphql_name 'PipelineSecurityReportFindingSort'
      description 'Pipeline security report finding sort values'

      # rubocop:disable Graphql/EnumValues -- https://gitlab.com/gitlab-org/gitlab/-/merge_requests/142773#note_1766354167
      value 'severity_desc', description: 'Severity in descending order.'
      value 'severity_asc', description: 'Severity in ascending order.'
      # rubocop:enable Graphql/EnumValues
    end
  end
end
