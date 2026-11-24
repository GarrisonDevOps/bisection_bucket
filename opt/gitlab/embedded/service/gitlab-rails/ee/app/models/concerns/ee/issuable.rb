# frozen_string_literal: true

module EE
  module Issuable
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include Ai::Model
    end

    def supports_epic?
      false
    end

    def supports_weight?
      false
    end

    def weight_available?
      supports_weight?
    end

    def sla_available?
      false
    end

    def escalation_policies_available?
      return false unless supports_escalation?

      ::Gitlab::IncidentManagement.escalation_policies_available?(project)
    end

    def metric_images_available?
      return false unless IssuableMetricImage.available_for?(project)

      supports_metric_images?
    end

    def issuable_resource_links_available?
      supports_resource_links? &&
        ::Gitlab::IncidentManagement.issuable_resource_links_available?(project)
    end

    def supports_sla?
      incident_type_issue?
    end

    def supports_metric_images?
      incident_type_issue?
    end

    def supports_resource_links?
      incident_type_issue?
    end

    override :allows_scoped_labels?
    def allows_scoped_labels?
      resource_parent.licensed_feature_available?(:scoped_labels)
    end

    def supports_iterations?
      false
    end

    def supports_approval_rules?
      is_a?(MergeRequest)
    end

    def supports_status?
      return false unless is_a?(Issue)
      return false unless resource_parent&.licensed_feature_available?(:work_item_status)

      # Types whose status support is still behind a feature flag (epic) are only
      # status-capable when the flag is enabled for the root ancestor. All other
      # Issue-backed types keep the license-only behavior.
      ::WorkItems::Statuses::FeatureFlags.status_enabled_for_base_type?(
        work_item_type.base_type, resource_parent.root_ancestor
      )
    end

    override :hook_association_changes
    def hook_association_changes(old_associations)
      changes = super

      if supports_escalation? && escalation_status
        current_escalation_policy = escalation_status.policy
        old_escalation_policy = old_associations.fetch(:escalation_policy, current_escalation_policy)

        if old_escalation_policy != current_escalation_policy
          changes[:escalation_policy] = [old_escalation_policy&.hook_attrs, current_escalation_policy&.hook_attrs]
        end
      end

      if supports_approval_rules?
        approval_rules_hook_attributes = approval_rules.map(&:hook_attrs)
        if old_approval_rules(old_associations) != approval_rules_hook_attributes
          changes[:approval_rules] = [old_approval_rules(old_associations), approval_rules_hook_attributes]
        end
      end

      if supports_status? && (old_current_status(old_associations) != status_with_fallback)
        changes[:status] = [old_current_status(old_associations)&.hook_attrs, status_with_fallback&.hook_attrs]
      end

      changes
    end

    private

    def old_approval_rules(assoc)
      @_old_approval_rules ||= assoc.fetch(:approval_rules) { approval_rules.map(&:hook_attrs) }
    end

    def old_current_status(assoc)
      @_old_current_status ||= assoc.fetch(:status, status_with_fallback)
    end
  end
end
