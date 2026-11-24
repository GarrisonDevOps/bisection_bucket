# frozen_string_literal: true

module Namespaces
  module Export
    class MembersTypeCombinator
      attr_reader :entity

      def initialize(entity)
        @entity = entity
      end

      def execute(entity_members, inherited_members)
        # first we select only the members who are really direct
        # in entity_members we will have only shared members remained
        direct_members = entity_members.extract! { |member| direct_member?(member) }
        direct_user_ids = direct_members.map(&:user_id)

        indirect_members = []
        overridden_shared_members = []

        inherited_members.each do |inherited_member|
          shared_member = shared_membership_for(inherited_member, entity_members)
          type = membership_type(inherited_member, shared_member, direct_user_ids, entity_members)

          next if type == :direct

          overridden_shared_members << shared_member if type == :shared
          indirect_members << inherited_member
        end

        shared_members = entity_members - overridden_shared_members

        # we return combination of direct, inherited and shared members
        direct_members + indirect_members + shared_members
      end

      private

      def shared_membership_for(member, entity_members)
        entity_members.find { |m| m.user_id == member.user_id }
      end

      def membership_type(member, shared_member, direct_user_ids, entity_members)
        return :direct if direct_user_ids.include?(member.user_id)

        return :indirect if entity_members.blank? # we can skip if we don't have any further group members

        return :indirect unless shared_member

        return :direct if member.access_level < shared_member.access_level

        :shared
      end

      def direct_member?(member)
        member.source == entity
      end
    end
  end
end
