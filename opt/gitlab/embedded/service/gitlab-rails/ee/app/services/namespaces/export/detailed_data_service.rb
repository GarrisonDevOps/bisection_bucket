# frozen_string_literal: true

module Namespaces
  module Export
    class DetailedDataService < BaseService
      def execute
        return service_not_available unless Feature.enabled?(:members_permissions_detailed_export, container)

        super
      end

      private

      def data
        MembershipCollector.new(container, current_user).execute
      end

      def header_to_value_hash
        {
          'Name' => ->(member) { member.name },
          'Username' => ->(member) { member.username },
          'Email' => ->(member) { member.email },
          'Path' => ->(member) { member.membershipable_path },
          'Group or project name' => ->(member) { member.membershipable_name },
          'Type' => ->(member) { member.membershipable_type },
          'Role' => ->(member) { member.role },
          'Role type' => ->(member) { member.role_type },
          'Membership type' => ->(member) { member.membership_type },
          'Membership status' => ->(member) { member.membership_status },
          'Membership source' => ->(member) { member.membership_source },
          'Access granted' => ->(member) { member.access_granted },
          'Access expiration' => ->(member) { member.access_expiration },
          'Last activity' => ->(member) { member.last_activity }
        }
      end
    end
  end
end
