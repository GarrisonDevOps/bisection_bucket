# frozen_string_literal: true

module EE
  module Ci
    module TroubleshootJobPolicyHelper
      extend ActiveSupport::Concern

      included do
        attr_reader :user

        condition(:troubleshoot_job_cloud_connector_authorized) do
          next false unless user

          user.allowed_to_use?(:troubleshoot_job)
        end

        condition(:troubleshoot_job_with_ai_authorized) do
          ::Gitlab::Llm::Chain::Utils::ChatAuthorizer.resource(
            resource: subject.project,
            user: user
          ).allowed?
        end

        condition(:troubleshoot_job_licensed, scope: :subject) do
          subject.project.licensed_feature_available?(:troubleshoot_job)
        end
      end
    end
  end
end
