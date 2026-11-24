# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    class OrganizationReaggregationWorker
      include ApplicationWorker
      include LoopWithRuntimeLimit

      MAX_RUNTIME = 270.seconds

      idempotent!
      # Keep the key while the job runs, so the next cron tick can't queue a second run
      # for the same organization.
      deduplicate :until_executed

      data_consistency :sticky
      feature_category :value_stream_management

      # The next ReaggregationWorker cron run picks up any remaining aggregations.
      sidekiq_options retry: false
      concurrency_limit -> { 10 }

      # @param organization_id [Integer, nil] nil runs instance-wide while vsa_aggregation_per_organization
      #   is disabled; remove with the flag: https://gitlab.com/gitlab-org/gitlab/-/work_items/636944
      # @return [void]
      def perform(organization_id)
        if organization_id
          organization = Organizations::Organization.find_by_id(organization_id)
          return unless organization
        end

        current_time = Time.current

        loop_with_runtime_limit(MAX_RUNTIME) do |runtime_limiter|
          batch = Analytics::CycleAnalytics::Aggregation.load_batch(current_time, :last_full_run_at,
            organization: organization)
          break if batch.empty?

          batch.each do |aggregation|
            Analytics::CycleAnalytics::NamespaceAggregatorService.new(aggregation: aggregation, mode: :full,
              runtime_limiter: runtime_limiter).execute

            break if runtime_limiter.over_time?
          end
        end
      end
    end
  end
end
