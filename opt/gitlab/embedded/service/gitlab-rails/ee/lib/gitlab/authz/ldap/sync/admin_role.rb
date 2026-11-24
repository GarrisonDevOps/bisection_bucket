# frozen_string_literal: true

module Gitlab
  module Authz
    module Ldap
      module Sync
        class AdminRole < ::Gitlab::Auth::Ldap::Sync::Base
          include Gitlab::Utils::StrongMemoize

          class << self
            def execute_all_providers
              ::Gitlab::AppLogger.debug 'Started LDAP admin role sync for all providers'

              ::Gitlab::Auth::Ldap::Config.providers.each do |provider|
                new(provider).execute
              end

              ::Gitlab::AppLogger.debug 'Finished LDAP admin role sync for all providers'
            end
          end

          attr_reader :provider, :proxy

          def initialize(provider)
            @provider = provider

            adapter = Gitlab::Auth::Ldap::Adapter.new(provider)
            @proxy = EE::Gitlab::Auth::Ldap::Sync::Proxy.new(provider, adapter)
          end

          def execute
            unless sync_enabled?
              logger.warn(message: 'LDAP admin role sync is not enabled.', provider: provider)
              return
            end

            # all syncs for a provider need to be run at the same time,
            # in case a user exists in multiple LDAP groups
            # hence, if any of the syncs are running for a provider, skip
            if ldap_admin_role_links.running.exists?
              logger.warn(message: 'LDAP admin role sync is already running.', provider: provider)
              return
            end

            begin
              ldap_admin_role_links.mark_syncs_as_running

              computed_admin_roles = {}

              ldap_admin_role_links.each do |admin_role_link|
                compute_admin_roles!(computed_admin_roles, admin_role_link)
              end

              update_existing_admin_roles(computed_admin_roles)
              assign_new_admin_roles(computed_admin_roles)

              ldap_admin_role_links.mark_syncs_as_successful

              logger.debug(message: 'Finished LDAP admin role sync for provider.', provider: provider)

            rescue StandardError => e
              ldap_admin_role_links.mark_syncs_as_failed(e.message)

              logger.error(message: 'Error during LDAP admin role sync for provider.', provider: provider)
            end
          end

          private

          def sync_enabled?
            ::License.feature_available?(:custom_roles)
          end

          def extract_admin_roles?
            Feature.enabled?(:extract_admin_roles_from_member_roles, :instance)
          end
          strong_memoize_attr :extract_admin_roles?

          def ldap_admin_role_links
            links = ::Authz::LdapAdminRoleLink.with_provider(provider)

            extract_admin_roles? ? links.preload_authz_admin_role : links.preload_admin_role
          end
          strong_memoize_attr :ldap_admin_role_links

          def select_and_preload_user_member_roles
            if extract_admin_roles?
              ::Authz::UserAdminRole.with_identity_provider(provider).preload_user
            else
              ::Users::UserMemberRole.with_identity_provider(provider).preload_user
            end
          end

          def compute_admin_roles!(computed_admin_roles, admin_role_link)
            admin_role = extract_admin_roles? ? admin_role_link.admin_role : admin_role_link.member_role

            # Only possible before the admin_roles backfill. Its users lose the role until the copy exists.
            unless admin_role
              logger.warn(
                message: 'Skipping LDAP admin role link without an admin role',
                provider: provider,
                ldap_admin_role_link_id: admin_role_link.id
              )
              return
            end

            ldap_users = get_member_dns(admin_role_link)

            ldap_users.each do |user_dn|
              # if the user_dn doesn't already exist in computed_admin_roles, only then add
              computed_admin_roles[user_dn] = admin_role unless computed_admin_roles.has_key?(user_dn)
            end

            logger.debug(message: 'Computed admin roles', provider: provider)
          end

          def update_existing_admin_roles(computed_admin_roles)
            logger.debug(message: 'Updating existing admin roles', provider: provider)

            multiple_ldap_providers = ::Gitlab::Auth::Ldap::Config.providers.count > 1

            existing_user_member_roles = select_and_preload_user_member_roles

            ldap_identity_by_user_id = resolve_ldap_identities(for_users: existing_user_member_roles.map(&:user))

            existing_user_member_roles.each do |user_member_role|
              user = user_member_role.user
              identity = ldap_identity_by_user_id[user.id]

              # Skip if this is not an LDAP user with a valid `extern_uid`.
              next unless identity.present? && identity.extern_uid.present?

              user_dn = identity.extern_uid

              # Prevent shifting roles, in case where user is a member
              # of two LDAP groups from different providers.
              # This is not ideal, but preserves existing behavior.
              if multiple_ldap_providers && user.ldap_identity.id != identity.id
                computed_admin_roles.delete(user_dn)
                next
              end

              desired_admin_role = computed_admin_roles[user_dn]

              if desired_admin_role.present?
                # Delete this entry from the hash now that we're acting on it
                computed_admin_roles.delete(user_dn)

                # Don't do anything if the user already has the desired admin role
                next if assigned_role_id(user_member_role) == desired_admin_role.id

                assign_or_update_admin_role(user, desired_admin_role)
              else
                # User is no longer in the LDAP group, remove the role
                user_member_role.destroy

                logger.debug(
                  message: 'Successfully un-assigned admin role from user',
                  username: user.username
                )
              end
            end
          end

          def assign_new_admin_roles(computed_admin_roles)
            logger.debug(message: 'Assigning admin roles to new users', provider: provider)

            return unless computed_admin_roles.present?

            gitlab_users_by_dn = resolve_users_from_normalized_dn(for_normalized_dns: computed_admin_roles.keys)

            computed_admin_roles.each do |user_dn, admin_role|
              user = gitlab_users_by_dn[user_dn]

              next if user&.admin? # rubocop: disable Cop/UserAdmin -- Not current_user so no need to check if admin mode is enabled

              if user.present?
                assign_or_update_admin_role(user, admin_role)
              else
                logger.debug(
                  message: 'User with DN should have but there is no user in GitLab with that identity',
                  provider: provider,
                  user_dn: user_dn
                )
              end
            end
          end

          def assigned_role_id(assignment)
            extract_admin_roles? ? assignment.admin_role_id : assignment.member_role_id
          end

          def assign_or_update_admin_role(user, admin_role)
            record = if extract_admin_roles?
                       ::Authz::UserAdminRole.create_or_update(user: user, admin_role: admin_role, ldap: true)
                     else
                       ::Users::UserMemberRole.create_or_update(user: user, member_role: admin_role, ldap: true)
                     end

            if record.valid?
              logger.debug(
                message: 'Successfully assigned admin role to user',
                admin_role_name: admin_role.name,
                username: user.username
              )
            else
              logger.error(
                message: 'Failed to assign admin role to user',
                admin_role_name: admin_role.name,
                username: user.username,
                error_message: record.errors.full_messages.join(', ')
              )
            end
          end

          def logger
            ::Gitlab::AppLogger
          end
        end
      end
    end
  end
end
