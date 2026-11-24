# frozen_string_literal: true

module Gitlab
  module Scim
    module Group
      class DeprovisioningService < ::Gitlab::Scim::BaseDeprovisioningService
        def initialize(identity)
          super

          @admin_bot = ::Users::Internal.in_organization(group.organization_id).admin_bot
        end

        def execute
          if group.last_owner?(user)
            return error(format(
              _(
                "Could not remove %{user} from %{group}. Cannot remove last group owner."),
              user: user.name,
              group: group.name
            )
                        )
          end

          ::Gitlab::Database::QueryAnalyzers::PreventCrossDatabaseModification.temporary_ignore_tables_in_transaction(
            %w[identities], url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/424287'
          ) do
            GroupScimIdentity.transaction do
              identity.update!(active: false)
              remove_group_access
            end
          end

          ServiceResponse.success(message: format(
            _("User %{user} was removed from %{group}."),
            user: user.name,
            group: group.name
          ))
        end

        private

        attr_reader :admin_bot

        def remove_group_access
          return unless group_membership

          ip_address = Gitlab::RequestContext.instance.client_ip

          ::Members::ScheduleDeletionService.new(
            group, user.id, admin_bot, ip_address: ip_address, reason: :scim_deprovisioning
          ).execute
        end

        def group_membership
          group.all_group_members.with_user(user).first
        end
        strong_memoize_attr :group_membership
      end
    end
  end
end
