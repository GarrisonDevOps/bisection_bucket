# frozen_string_literal: true

module Security
  module DependencyFirewall
    class RefreshGroupPreventedStatsWorker
      include ApplicationWorker
      prepend ::Geo::SkipSecondary

      data_consistency :sticky
      feature_category :dependency_firewall
      urgency :low
      idempotent!
      # Longer than the default 10 minutes so a job waiting behind the concurrency limit still absorbs
      # later refreshes of the same group.
      deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true, ttl: 2.hours
      concurrency_limit -> { 5 }
      sidekiq_options retry: 3
      defer_on_database_health_signal :gitlab_main, [:dependency_firewall_prevented_packages], 1.minute

      def self.schedule(group_ids)
        return if group_ids.empty?

        bulk_perform_async(group_ids.uniq.map { |group_id| [group_id] })
      end

      def perform(group_id)
        group = Group.find_by_id(group_id)
        return unless group && Availability.group_prevented_stats_enabled_for_root_id?(group.traversal_ids.first)

        PreventedStats::GroupRefreshService.new(group).execute
      end
    end
  end
end
