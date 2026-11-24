# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowFailureCategoryEnum < BaseEnum
        graphql_name 'DuoWorkflowFailureCategory'
        description 'Category of why a GitLab Duo Agent Platform session failed.'

        value 'USER_FIXABLE', value: 'user_fixable',
          description: 'Cause the user can fix, for example no runner.'
        value 'TRANSIENT', value: 'transient',
          description: 'Temporary cause, for example a timeout.'
        value 'STOPPED_PART_WAY', value: 'stopped_part_way',
          description: 'Session started and stopped part way, for example at a step limit.'
        value 'UNKNOWN', value: 'unknown',
          description: 'Unknown cause.'
      end
    end
  end
end
