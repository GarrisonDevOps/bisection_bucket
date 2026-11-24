# frozen_string_literal: true

module Types
  module Vulnerabilities
    class TriggeredWorkflowNameEnum < BaseEnum
      graphql_name 'VulnerabilityWorkflowName'
      description 'Workflow name for vulnerability triggered workflows'

      ::Vulnerabilities::TriggeredWorkflow::WORKFLOW_NAMES.each_key do |name|
        value name.to_s.upcase, value: name.to_s, description: "Workflow name is #{name.to_s.humanize.downcase}"
      end
    end
  end
end
