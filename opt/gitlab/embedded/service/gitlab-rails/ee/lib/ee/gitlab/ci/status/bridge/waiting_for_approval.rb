# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Status
        module Bridge
          module WaitingForApproval
            extend ActiveSupport::Concern

            prepended do
              prepend EE::Gitlab::Ci::Status::WaitingForApproval # rubocop: disable Cop/InjectEnterpriseEditionModule
            end

            def status_tooltip
              _('View deployment details page')
            end

            def deployment_details_path
              project_environment_deployment_path(subject.project, subject.deployment&.environment, subject.deployment)
            end
          end
        end
      end
    end
  end
end
