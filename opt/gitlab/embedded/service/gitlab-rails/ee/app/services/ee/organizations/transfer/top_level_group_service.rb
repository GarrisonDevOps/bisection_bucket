# frozen_string_literal: true

module EE
  module Organizations
    module Transfer
      module TopLevelGroupService
        extend ::Gitlab::Utils::Override
        include ::Organizations::Transfer::GroupTransferAuditing

        override :execute
        def execute
          source_organization_ids = groups.to_h { |group| [group.id, group.organization_id] }
          result = super

          log_audit_events(source_organization_ids) if result.success?

          result
        end

        private

        override :transfer_validation_error
        def transfer_validation_error
          return if new_organization.default?
          return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          multiple_subscriptions_error if multiple_group_subscriptions?
        end

        def multiple_group_subscriptions?
          group_ids = (existing_top_level_groups | groups).map(&:id)

          GitlabSubscription.many_active_paid_or_trial_for_namespaces?(group_ids)
        end

        def multiple_subscriptions_error
          s_(
            "TransferOrganization|There can only be one top-level group with a GitLab subscription in an Organization."
          )
        end

        def log_audit_events(source_organization_ids)
          groups.each do |group|
            source_organization_id = source_organization_ids[group.id]
            next if source_organization_id == new_organization.id

            log_group_transferred_audit_event(group, source_organization_id)
          end
        end
      end
    end
  end
end
