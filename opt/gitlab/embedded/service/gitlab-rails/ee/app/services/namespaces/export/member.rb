# frozen_string_literal: true

module Namespaces
  module Export
    class Member
      include ::ActiveModel::Attributes
      include ::ActiveModel::AttributeAssignment

      attribute :id, :integer
      attribute :name, :string
      attribute :username, :string
      attribute :email, :string
      attribute :membershipable_id, :integer
      attribute :membershipable_path, :string
      attribute :membershipable_name, :string
      attribute :membershipable_class, :string
      attribute :membershipable_type, :string
      attribute :role, :string
      attribute :role_type, :string
      attribute :membership_type, :string
      attribute :membership_status, :string
      attribute :membership_source, :string
      attribute :access_granted, :string
      attribute :access_expiration, :string
      attribute :access_level, :integer
      attribute :last_activity, :string

      def initialize(member, entity, parent_groups)
        super()

        map_attributes(member, entity, parent_groups)
      end

      def map_attributes(member, membershipable, parent_groups)
        assign_attributes(
          id: member.id,
          name: member.user&.name,
          username: member.user&.username,
          email: member.user&.email || member.invite_email,
          membershipable_id: membershipable.id,
          membershipable_path: membershipable.full_path,
          membershipable_name: membershipable.name,
          membershipable_type: get_membershipable_type(membershipable),
          membershipable_class: membershipable.class,
          access_level: member.access_level,
          role: member.present.human_access,
          role_type: member.present.role_type,
          membership_type: get_membership_type(member, membershipable, parent_groups),
          membership_status: member.present.pending? ? 'pending' : 'approved',
          membership_source: member.source.full_path,
          access_granted: member.created_at.iso8601,
          access_expiration: member.expires_at&.iso8601,
          last_activity: member.user&.last_activity_on&.iso8601
        )
      end

      private

      def get_membershipable_type(membershipable)
        if membershipable.is_a?(Project)
          'Project'
        elsif membershipable.is_a?(Group) && membershipable.parent_id
          'Sub Group'
        else
          'Group'
        end
      end

      def get_membership_type(member, membershipable, parent_groups)
        if member.source == membershipable
          'direct'
        elsif parent_groups.include?(member.source_id)
          'inherited'
        else
          'shared'
        end
      end
    end
  end
end
