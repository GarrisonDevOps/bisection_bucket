# frozen_string_literal: true

module Types
  module Ai
    module FunctionalVerificationCheck
      class StateEnum < BaseEnum
        graphql_name 'FunctionalVerificationState'
        description 'State of a GitLab Duo Agent Platform functional verification check.'

        value 'NOT_RUN', value: 'not_run', description: 'No verification run has been started yet.'
        value 'RUNNING', value: 'running', description: 'Verification run is in progress.'
        value 'PASSED', value: 'passed', description: 'Verification run finished successfully.'
        value 'FAILED', value: 'failed', description: 'Verification run finished but failed.'
      end
    end
  end
end
