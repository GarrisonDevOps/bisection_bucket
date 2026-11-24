# frozen_string_literal: true

module Gitlab
  module Auth
    module GroupSaml
      class MembershipUpdater
        include Gitlab::Utils::StrongMemoize
        include GitlabSubscriptions::MemberManagement::SeatAwareProvisioning

        attr_reader :user, :saml_provider, :auth_hash

        delegate :group, :default_membership_role, :member_role_id, to: :saml_provider

        def initialize(user, saml_provider, auth_hash)
          @user = user
          @saml_provider = saml_provider
          @auth_hash = auth_hash
        end

        def execute
          add_default_membership

          enqueue_group_sync if sync_groups?
        end

        private

        # Outside group sync user should only be added at default
        # membership role if they are otherwise not a member
        def add_default_membership
          return if group.member?(user)

          access_level_adjustment = calculate_adjusted_access_level(group, user, default_membership_role)
          member = group.add_member(user, access_level_adjustment.access_level, member_role_id: member_role_id)

          return unless member&.persisted?

          if access_level_adjustment.adjusted?
            track_and_audit_minimal_access_provisioning(
              group, member, default_membership_role, { saml_provider_id: saml_provider.id }
            )
          end

          log_audit_event(member: member)
        end

        def enqueue_group_sync
          return enqueue_microsoft_group_sync if microsoft_overage_sync?

          enqueue_saml_group_sync if saml_group_sync?
        end

        def sync_groups?
          user && any_group_links_in_hierarchy?
        end

        def saml_group_sync?
          group.saml_group_sync_available?
        end

        def microsoft_overage_sync?
          auth_hash.azure_group_overage_claim? && microsoft_group_sync_available?
        end

        def enqueue_saml_group_sync
          GroupSamlGroupSyncWorker.perform_async(user.id, group.id, group_link_ids)
        end

        def enqueue_microsoft_group_sync
          ::SystemAccess::GroupSamlMicrosoftGroupSyncWorker.perform_async(user.id, group.id)
        end

        # rubocop:disable CodeReuse/ActiveRecord
        def group_link_ids
          strong_memoize(:group_link_ids) do
            next [] if group_names_from_saml.empty?

            SamlGroupLink
              .by_saml_group_name(group_names_from_saml)
              .by_group_id(group_ids_in_hierarchy)
              .pluck(:id)
          end
        end

        def any_group_links_in_hierarchy?
          strong_memoize(:group_ids_with_any_links) do
            SamlGroupLink.by_group_id(group_ids_in_hierarchy).exists?
          end
        end

        def group_ids_in_hierarchy
          group.self_and_descendants.select(:id)
        end
        # rubocop:enable CodeReuse/ActiveRecord

        def group_names_from_saml
          strong_memoize(:group_names_from_saml) do
            auth_hash.groups || []
          end
        end

        def log_audit_event(member:)
          audit_context = {
            name: 'group_saml_member_added',
            author: user,
            scope: group,
            target: user,
            message: "Added as SAML group member",
            additional_details: {
              add: 'user_access',
              as: member.human_access,
              custom_message: "User #{user.name} added to group #{group.name} through SAML authentication"
            }
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def microsoft_group_sync_available?
          group.saml_group_sync_available? && group.licensed_feature_available?(:microsoft_group_sync) &&
            group.system_access_microsoft_application.present? && group.system_access_microsoft_application.enabled?
        end
      end
    end
  end
end
