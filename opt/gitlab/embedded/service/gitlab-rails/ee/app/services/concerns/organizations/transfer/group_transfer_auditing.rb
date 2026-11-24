# frozen_string_literal: true

module Organizations
  module Transfer
    module GroupTransferAuditing
      private

      # @param group [Group] the top-level group that moved
      # @param source_organization_id [Integer] the organization the group moved from
      # @return [void]
      def log_group_transferred_audit_event(group, source_organization_id)
        ::Gitlab::Audit::Auditor.audit(
          name: 'group_transferred_to_organization',
          author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          scope: group,
          target: new_organization,
          message: "Transferred group to organization #{new_organization.name}",
          additional_details: {
            source_organization_id: source_organization_id,
            target_organization_id: new_organization.id
          }
        )

        nil
      end
    end
  end
end
