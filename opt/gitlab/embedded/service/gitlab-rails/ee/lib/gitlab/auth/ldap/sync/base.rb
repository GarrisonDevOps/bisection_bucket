# frozen_string_literal: true

module Gitlab
  module Auth
    module Ldap
      module Sync
        class Base
          attr_reader :provider, :proxy

          private

          def get_member_dns(group_link)
            group_link.cn ? dns_for_group_cn(group_link.cn) : proxy.dns_for_filter(group_link.filter)
          end

          def dns_for_group_cn(group_cn)
            if config.group_base.blank?
              logger.debug(
                "No `group_base` configured for '#{provider}' provider and group link CN #{group_cn}. Skipping"
              )

              return
            end

            proxy.dns_for_group_cn(group_cn)
          end

          # returns a hash user_id -> LDAP identity in current LDAP provider
          def resolve_ldap_identities(for_users:)
            ::Identity.for_user(for_users).with_provider(provider)
                      .index_by(&:user_id)
          end

          def resolve_ldap_identities_by_ids(for_user_ids:)
            ::Identity.for_user_ids(for_user_ids).with_provider(provider).index_by(&:user_id)
          end

          # returns a hash of normalized DN -> user for the current LDAP provider
          # rubocop: disable CodeReuse/ActiveRecord -- old class method
          def resolve_users_from_normalized_dn(for_normalized_dns:)
            ::Identity.with_provider(provider).iwhere(extern_uid: for_normalized_dns)
                      .preload(:user)
                      .to_h { |identity| [identity.extern_uid, identity.user] }
          end
          # rubocop: enable CodeReuse/ActiveRecord

          def logger
            ::Gitlab::AppLogger
          end

          def config
            @proxy.adapter.config
          end
        end
      end
    end
  end
end
