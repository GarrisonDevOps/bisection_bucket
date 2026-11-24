# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      class SortEnum < BaseEnum
        graphql_name 'AiFlowTriggerSort'
        description 'Values for sorting AI flow triggers.'

        value 'NAME_ASC', 'Name by ascending order.', value: :name_asc
        value 'NAME_DESC', 'Name by descending order.', value: :name_desc
        value 'CREATED_ASC', 'Created at ascending order.', value: :created_asc
        value 'CREATED_DESC', 'Created at descending order.', value: :created_desc
        value 'UPDATED_ASC', 'Updated at ascending order.', value: :updated_asc
        value 'UPDATED_DESC', 'Updated at descending order.', value: :updated_desc
        value 'LAST_RUN_ASC', 'Last run at ascending order. Flow triggers that never ran come last.',
          value: :last_run_asc
        value 'LAST_RUN_DESC', 'Last run at descending order. Flow triggers that never ran come last.',
          value: :last_run_desc
        value 'TOTAL_RUNS_ASC', 'Number of runs in the last 30 days by ascending order.', value: :total_runs_asc
        value 'TOTAL_RUNS_DESC', 'Number of runs in the last 30 days by descending order.', value: :total_runs_desc
      end
    end
  end
end
