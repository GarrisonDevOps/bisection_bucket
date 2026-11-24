# frozen_string_literal: true

module EE
  module Groups
    module GroupLinks
      module CreateService
        extend ::Gitlab::Utils::Override
        include GroupLinksHelper

        override :after_successful_save
        def after_successful_save
          super

          log_audit_event
          update_user_group_member_roles
        end

        private

        override :remove_unallowed_params
        def remove_unallowed_params
          params.delete(:member_role_id) unless group&.custom_roles_enabled?

          super
        end

        def log_audit_event
          audit_context = {
            name: "group_share_with_group_link_created",
            author: current_user,
            scope: link.shared_group,
            target: link.shared_with_group,
            stream_only: false,
            message: "Invited #{link.shared_with_group.name} " \
                     "to the group #{link.shared_group.name}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def update_user_group_member_roles
          ::Authz::UserGroupMemberRoles::UpdateForSharedGroupWorker.perform_async(link.id)
        end
      end
    end
  end
end
