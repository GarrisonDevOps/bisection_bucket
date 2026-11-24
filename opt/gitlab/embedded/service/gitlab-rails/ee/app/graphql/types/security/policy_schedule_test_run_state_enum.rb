# frozen_string_literal: true

module Types
  module Security
    class PolicyScheduleTestRunStateEnum < BaseEnum
      graphql_name 'PolicyScheduleTestRunState'
      description 'State of a policy schedule test run.'

      value 'PENDING', value: 'pending', description: 'Test run is pending and waiting for pipeline creation.'
      value 'CREATING', value: 'creating', description: 'Test run is creating the pipeline.'
      value 'RUNNING', value: 'running', description: 'Test run is in progress.'
      value 'COMPLETE', value: 'complete', description: 'Test run completed successfully.'
      value 'FAILED', value: 'failed', description: 'Test run failed.'
    end
  end
end
