# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowSortEnum < SortEnum
        graphql_name 'DuoWorkflowsWorkflowSort'
        description 'Values for sorting Duo Workflows.'

        value 'STATUS_ASC', 'By status ascending order.', value: :status_asc
        value 'STATUS_DESC', 'By status descending order.', value: :status_desc
      end
    end
  end
end
