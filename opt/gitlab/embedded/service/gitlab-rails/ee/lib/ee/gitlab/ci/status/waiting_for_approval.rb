# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Status
        module WaitingForApproval
          extend ActiveSupport::Concern

          def illustration
            {
              image: 'illustrations/empty-state/empty-job-manual-md.svg',
              size: '',
              title: _('Waiting for approvals'),
              content: format(
                _("This job deploys to the protected environment \"%{environment}\", which requires approvals. " \
                  "You can approve or reject the deployment on the deployment details page."),
                environment: subject.deployment&.environment&.name
              )
            }
          end

          def has_action?
            true
          end

          def action_icon
            nil
          end

          def action_title
            nil
          end

          def action_button_title
            _('View deployment details page')
          end

          def action_path
            project_environment_deployment_path(subject.project, subject.deployment&.environment, subject.deployment)
          end

          def action_method
            :get
          end

          class_methods do
            extend ::Gitlab::Utils::Override

            override :matches?
            def matches?(job, _user)
              job.waiting_for_deployment_approval?
            end
          end
        end
      end
    end
  end
end
