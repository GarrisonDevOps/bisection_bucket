# frozen_string_literal: true

module Resolvers
  module Security
    class TriageAndRemediationCoverageCountersResolver < BaseResolver
      type ::Types::Security::TriageAndRemediationCoverageCountersType, null: true
      authorize :read_security_scan_profiles
      authorizes_object!

      argument :trigger_type, ::Types::Security::ScanProfileTriggerTypeEnum,
        required: false,
        description: 'Trigger type to count coverage for. Counts any triage and remediation trigger type when omitted.'

      alias_method :group, :object

      def resolve(trigger_type: nil)
        bitmask = ::Security::TriageCoverage::CapabilityBitmask
        mask = trigger_type ? bitmask.mask_for(trigger_type) : bitmask::ALL_MASK
        return unless mask

        Gitlab::Graphql::Lazy.with_value(missing_flows_mask) do |missing_mask|
          counts = ::Security::InventoryFilter.triage_coverage_counts_for(group, mask, missing_mask)

          ::Types::Security::TriageAndRemediationCoverageCountersType::Adapter.new(
            enabled_count: counts.enabled_count, auto_count: counts.auto_count,
            flow_missing_count: counts.flow_missing_count, group: group
          )
        end
      end

      private

      def missing_flows_mask
        BatchLoader::GraphQL.for(group.traversal_ids.first).batch do |root_ids, loader|
          masks = ::Security::TriageCoverage::ProjectCapabilities.missing_flows_masks(root_ids)

          masks.each { |root_id, mask| loader.call(root_id, mask) }
        end
      end
    end
  end
end
