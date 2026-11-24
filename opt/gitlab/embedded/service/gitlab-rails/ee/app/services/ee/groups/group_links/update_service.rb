# frozen_string_literal: true

module EE
  module Groups
    module GroupLinks
      module UpdateService
        extend ::Gitlab::Utils::Override
        include GroupLinksHelper

        override :execute
        def execute(group_link_params)
          super.tap do |group_link|
            update_user_group_member_roles(group_link)
            log_audit_event(group_link)
          end
        end

        private

        override :remove_unallowed_params
        def remove_unallowed_params
          if group_link_params[:member_role_id] && !group_link.shared_group.custom_roles_enabled?
            group_link_params.delete(:member_role_id)
          end

          super
        end

        def log_audit_event(group_link)
          return unless changes.present?

          audit_context = {
            name: "group_share_with_group_link_updated",
            author: current_user,
            scope: group_link.shared_group,
            target: group_link.shared_with_group,
            stream_only: false,
            message: "Updated #{group_link.shared_with_group.name}'s " \
                     "access params for the group #{group_link.shared_group.name}",
            additional_details: {
              changes: [
                change_details(:group_access, formatter: ->(v) { ::Gitlab::Access.human_access(v) }),
                change_details(:expires_at),
                change_details(:member_role_id, name: :member_role)
              ].compact
            }.compact
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def change_details(attr, name: nil, formatter: ->(v) { v.to_s })
          change = changes[attr]
          return if change.blank?

          { change: name || attr, from: formatter.call(change.first), to: formatter.call(change.last) }
        end

        def changes
          @changes ||= group_link.previous_changes.symbolize_keys.except(:updated_at)
        end

        def update_user_group_member_roles(link)
          member_role_changed = changes[:member_role_id].present?
          access_level_changed = changes[:group_access].present?

          return unless member_role_changed || access_level_changed

          ::Authz::UserGroupMemberRoles::UpdateForSharedGroupWorker.perform_async(link.id)
        end
      end
    end
  end
end
