# frozen_string_literal: true

module Members
  class MembershipModifiedByAdminCloudEvent < ::Members::BaseEvent
    event_type :membership_modified_by_admin

    class << self
      # Membership can be modified by an admin (Members::CreateService) or by a
      # system flow with no acting admin (group and LDAP sync). `current_user`
      # may be nil for those flows; CloudEvents support a nil actor, so we pass
      # it through rather than misattributing the action to a bot. We derive
      # source/subject/organization from the member's source (group or project).
      #
      # `source` is accepted as a keyword argument so callers that already hold
      # the member source (for example when publishing for a batch of members)
      # do not re-fetch the association for every member.
      def build(member:, current_user: nil, source: member.source)
        raise ArgumentError, 'source is required' unless source

        organization = source.organization

        build_cloud_event(
          source: "#{source.class.name.downcase.pluralize}/#{source.id}",
          subject: "members/#{source.class.name.downcase}/#{source.id}",
          current_user: current_user,
          organization: organization,
          event_data: { member_user_id: member.user_id }
        )
      end
    end

    private

    # This event's payload is only `member_user_id`, so we drop the base
    # source_id/source_type properties inherited from Members::BaseEvent.
    def base_properties
      {}
    end

    def base_required
      []
    end

    def additional_properties
      { 'member_user_id' => { 'type' => 'integer' } }
    end

    def additional_required
      %w[member_user_id]
    end
  end
end
