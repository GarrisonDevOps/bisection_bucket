# frozen_string_literal: true

module Namespaces
  module Export
    class LimitedDataService < BaseService
      private

      def data
        GroupMembersFinder.new(container, current_user).execute(include_relations: [:descendants, :direct, :inherited])
      end

      def header_to_value_hash
        {
          'Username' => ->(member) { member&.user&.username },
          'Name' => ->(member) { member&.user&.name },
          'Access granted' => ->(member) { member.created_at.to_fs(:csv) },
          'Access expires' => ->(member) { member.expires_at },
          'Max role' => ->(member) { member.present.access_level_for_export },
          'Source' => ->(member) { member_source(member) }
        }
      end
    end
  end
end
