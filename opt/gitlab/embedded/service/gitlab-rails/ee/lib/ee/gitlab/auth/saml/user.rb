# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      module Saml
        module User
          extend ::Gitlab::Utils::Override

          override :find_user
          def find_user
            user = super

            if user_in_required_group?
              unblock_user(user, "in required group") if user&.persisted? && user.ldap_blocked?
            elsif user&.persisted?
              block_user(user, "not in required group") unless user.blocked?
            else
              user = nil
            end

            if user
              # Check if there is overlap between the user's groups and the admin/auditor groups
              # setting then set user as admin, auditor, or neither.
              user.admin = !(auth_hash.groups & saml_config.admin_groups).empty? if admin_groups_enabled?
              user.auditor = !(auth_hash.groups & saml_config.auditor_groups).empty? if auditor_groups_enabled?
            end

            user
          end

          override :find_and_update!
          def find_and_update!
            save

            update_group_membership
            update_duo_add_on_assignment
            gl_user
          end

          protected

          def block_user(user, reason)
            blocked = user.system_block

            log_user_changes(user, 'SAML', "#{reason}, blocking")
            log_audit_event_for_block(user, reason) if blocked
          end

          def log_audit_event_for_block(user, reason)
            ::Gitlab::Audit::Auditor.audit(
              name: 'user_blocked_by_saml_required_group',
              message: 'Blocked user by SAML required group',
              author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
              scope: user,
              target: user,
              target_details: user.username,
              additional_details: {
                system_event: true,
                reason: reason,
                provider: auth_hash.provider,
                extern_uid: auth_hash.uid
              }
            )
          end

          def unblock_user(user, reason)
            user.activate
            log_user_changes(user, 'SAML', "#{reason}, unblocking")
          end

          def user_in_required_group?
            required_groups = saml_config.required_groups
            required_groups.empty? || !(auth_hash.groups & required_groups).empty?
          end

          def admin_groups_enabled?
            !saml_config.admin_groups.blank?
          end

          def auditor_groups_enabled?
            !saml_config.auditor_groups.blank?
          end

          def update_duo_add_on_assignment
            ::Gitlab::Auth::Saml::DuoAddOnAssignmentUpdater.new(gl_user, auth_hash).execute
          end

          def update_group_membership
            ::Gitlab::Auth::Saml::MembershipUpdater.new(gl_user, auth_hash).execute
          end
        end
      end
    end
  end
end
