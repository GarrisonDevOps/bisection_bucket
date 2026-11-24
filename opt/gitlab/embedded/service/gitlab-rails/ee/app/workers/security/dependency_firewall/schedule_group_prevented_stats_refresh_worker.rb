# frozen_string_literal: true

module Security
  module DependencyFirewall
    class ScheduleGroupPreventedStatsRefreshWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :dependency_firewall
      concurrency_limit -> { 5 }

      def self.dispatch?(event)
        root_namespace_ids_for(event).any? do |root_id|
          Availability.group_prevented_stats_enabled_for_root_id?(root_id)
        end
      end

      def self.root_namespace_ids_for(event)
        data = event.data

        case event
        when ::Projects::ProjectTransferedEvent, ::Groups::GroupTransferedEvent
          [data[:old_root_namespace_id], data[:new_root_namespace_id]]
        else
          [data[:root_namespace_id]]
        end.compact.uniq
      end
      private_class_method :root_namespace_ids_for

      def handle_event(event)
        group_ids = ::Security::DependencyFirewall::PreventedStats::AffectedGroups.for_namespaces(namespace_ids_for(event))
        ::Security::DependencyFirewall::RefreshGroupPreventedStatsWorker.schedule(group_ids)
      end

      private

      def namespace_ids_for(event)
        data = event.data

        case event
        when ::Projects::ProjectTransferedEvent
          [data[:old_namespace_id], data[:new_namespace_id]]
        when ::Projects::ProjectDeletedEvent
          [data[:namespace_id]]
        when ::Groups::GroupTransferedEvent
          [data[:group_id], data[:old_root_namespace_id]]
        when ::Groups::GroupDeletedEvent
          [data[:parent_namespace_id]]
        else
          []
        end.compact
      end
    end
  end
end
