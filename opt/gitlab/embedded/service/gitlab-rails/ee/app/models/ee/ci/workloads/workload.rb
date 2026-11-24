# frozen_string_literal: true

module EE
  module Ci
    module Workloads
      module Workload
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          has_many :workflows_workloads, class_name: 'Ai::DuoWorkflows::WorkflowsWorkload'
          has_many :workflows, through: :workflows_workloads, disable_joins: true
        end

        def latest_workflow
          workflows.order(id: :desc).first
        end
      end
    end
  end
end
