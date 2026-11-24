# frozen_string_literal: true

module Resolvers
  module Security
    class TriageAndRemediationFlowStatusesResolver < BaseResolver
      type [::Types::Security::TriageAndRemediationTriggerFlowStatusType], null: true
      authorize :read_security_scan_profiles
      authorizes_object!

      alias_method :group, :object

      # Flow availability belongs to the root group and is shared by its subgroups: resolve it once per batch.
      def resolve
        BatchLoader::GraphQL.for(group.traversal_ids.first).batch do |root_ids, loader|
          statuses_by_root = ::Security::TriageCoverage::FlowStatuses.for_root_ids(root_ids)

          root_ids.each do |root_id|
            statuses = statuses_by_root.fetch(root_id, ::Security::TriageCoverage::FlowStatuses::UNRESOLVED)
            loader.call(root_id, statuses.map do |type, status|
              { trigger_type: type.to_s, flow_status: status.to_s, flow_name: flow_name(type) }
            end)
          end
        end
      end

      private

      def flow_name(trigger_type)
        ::Security::TriageCoverage::FlowStatuses::FLOW_BY_TRIGGER[trigger_type]&.call&.translated_display_name
      end
    end
  end
end
