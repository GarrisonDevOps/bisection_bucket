# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      module Ldap
        # Create a hash map of member DNs to access levels. The highest
        # access level is retained in cases where `set` is called multiple times
        # for the same DN.

        # Prioritization logic:
        # 1. Higher base_access_level takes precedence over lower base_access_level
        # 2. When base_access_levels are equal, custom roles (with member_role_id)
        #    take precedence over default roles (without member_role_id)
        class AccessLevels < Hash
          def set(dns, to:)
            dns.each do |dn|
              current = self[dn]

              # Keep the higher of the access values.
              self[dn] = to if current.nil? ||
                to[:base_access_level] > current[:base_access_level] ||
                (
                  to[:base_access_level] == current[:base_access_level] &&
                  to[:member_role_id].present? && current[:member_role_id].nil?
                )
            end
          end
        end
      end
    end
  end
end
