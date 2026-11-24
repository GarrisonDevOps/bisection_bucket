# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowsWorkload < ::ApplicationRecord
      self.table_name = :duo_workflows_workloads
      belongs_to :workflow, class_name: 'Ai::DuoWorkflows::Workflow'
      belongs_to :workload, class_name: 'Ci::Workloads::Workload'
      belongs_to :project

      validates :project, presence: true
      validates :workflow, presence: true
      validates :workload, presence: true
    end
  end
end
