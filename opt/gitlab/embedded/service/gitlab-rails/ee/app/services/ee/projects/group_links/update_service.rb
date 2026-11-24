# frozen_string_literal: true

module EE
  module Projects
    module GroupLinks
      module UpdateService
        extend ::Gitlab::Utils::Override
        include ProjectLinksHelper

        override :execute
        def execute(group_link_params)
          super.tap do
            update_user_project_member_roles
            send_audit_event
          end
        end

        private

        override :permitted_attributes
        def permitted_attributes
          return super unless custom_role_for_project_link_enabled?(group_link.project)

          super + %i[member_role_id]
        end

        def send_audit_event
          return unless saved_changes_present?

          message, details = audit_message

          audit_context = {
            name: 'project_group_link_updated',
            author: current_user,
            scope: project,
            target: group_link.group,
            message: message,
            additional_details: details
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def saved_changes_present?
          group_link.saved_changes['group_access'].present? || group_link.saved_changes['expires_at'].present?
        end

        def audit_message
          changes = []
          details = { change: {} }

          if group_link.saved_changes['group_access'].present?
            old_value, new_value = group_link.saved_changes['group_access'].map { |v| ::Gitlab::Access.human_access(v) }
            property = :group_access
            changes << "profile #{property} from #{old_value} to #{new_value}"
            details[:change].update({ access_level: { from: old_value, to: new_value } })
          end

          if group_link.saved_changes['expires_at'].present?
            old_value, new_value = group_link.saved_changes['expires_at']
            property = :expires_at
            changes << "profile #{property} from #{old_value || 'nil'} to #{new_value || 'nil'}"
            details[:change].update({ invite_expiry: { from: old_value || 'nil', to: new_value || 'nil' } })
          end

          ["Changed project group link #{changes.join(' ')}", details]
        end

        def update_user_project_member_roles
          return if ::Feature.disabled?(:cache_user_project_member_roles, group_link.project.root_ancestor)

          member_role_changed = group_link.saved_changes['member_role_id'].present?
          access_level_changed = group_link.saved_changes['group_access'].present?

          return unless member_role_changed || access_level_changed

          ::Authz::UserProjectMemberRoles::UpdateForSharedProjectWorker.perform_async(group_link.id)
        end
      end
    end
  end
end
