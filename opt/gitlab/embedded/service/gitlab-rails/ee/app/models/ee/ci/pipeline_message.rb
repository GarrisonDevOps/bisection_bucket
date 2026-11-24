# frozen_string_literal: true

module EE
  module Ci
    module PipelineMessage
      extend ActiveSupport::Concern

      PIPELINE_EXECUTION_POLICY_ERROR = 'Pipeline execution policy error:'

      prepended do
        scope :pipeline_execution_policy_failure, -> {
          where("content LIKE ?", "#{sanitize_sql_like(PIPELINE_EXECUTION_POLICY_ERROR)}%").where(severity: :error)
        }
      end
    end
  end
end
