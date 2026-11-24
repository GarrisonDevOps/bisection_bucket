# frozen_string_literal: true

module EE
  module Types
    module MergeRequests
      module DetailedMergeStatusEnum
        extend ActiveSupport::Concern

        prepended do
          value 'REQUESTED_CHANGES',
            value: :requested_changes,
            description: 'Indicates a reviewer has requested changes.'
          value 'SECURITY_POLICY_PIPELINE_CHECK',
            value: :security_policy_pipeline_check,
            description: 'All security policy pipelines must succeed.'
        end
      end
    end
  end
end
