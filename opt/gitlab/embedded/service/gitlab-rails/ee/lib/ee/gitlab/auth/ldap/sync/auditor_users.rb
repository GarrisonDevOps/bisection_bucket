# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      module Ldap
        module Sync
          class AuditorUsers < Sync::Users # rubocop:disable Gitlab/EeOnlyClass -- mirrors AdminUsers, an existing EE-only sync class with no CE counterpart to extend
            private

            def attribute
              :auditor
            end

            def member_dns
              return [] if audit_group.empty?

              proxy.dns_for_group_cn(audit_group)
            end

            def audit_group
              proxy.adapter.config.audit_group
            end
          end
        end
      end
    end
  end
end
