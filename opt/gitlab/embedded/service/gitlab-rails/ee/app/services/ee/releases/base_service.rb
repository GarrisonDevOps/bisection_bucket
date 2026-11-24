# frozen_string_literal: true

module EE
  module Releases
    module BaseService
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        def project_group_id
          project.group&.id
        end

        def audit(release, action:)
          if action == :milestones_updated
            milestones = release.milestone_titles.presence || '[none]'
            message = "Milestones associated with release changed to #{milestones}"
          else
            message = "#{action.to_s.upcase_first} release #{release.tag}"
          end

          if action == :created && release.milestones.count > 0
            message += " with #{'Milestone'.pluralize(release.milestones.count)} " +
              release.milestone_titles
          end

          event_type = "release_#{action}"
          event_type = "#{event_type}_audit_event" if action == :deleted

          audit_context = {
            name: event_type,
            author: current_user,
            target: release,
            scope: project,
            message: message,
            target_details: release.name
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
