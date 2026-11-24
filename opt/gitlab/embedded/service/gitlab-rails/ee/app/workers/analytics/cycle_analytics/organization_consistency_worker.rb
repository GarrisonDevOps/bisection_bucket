# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    class OrganizationConsistencyWorker
      include ApplicationWorker
      include LoopWithRuntimeLimit

      idempotent!
      # Keep the key while the job runs, so the next cron tick can't queue a second run
      # for the same organization.
      deduplicate :until_executed

      data_consistency :sticky
      feature_category :value_stream_management

      # The next ConsistencyWorker cron run picks up any remaining aggregations.
      sidekiq_options retry: false
      concurrency_limit -> { 10 }

      MAX_RUNTIME = 200.seconds

      # @param organization_id [Integer, nil] nil runs instance-wide while vsa_aggregation_per_organization
      #   is disabled; remove with the flag: https://gitlab.com/gitlab-org/gitlab/-/work_items/636944
      # @return [void]
      def perform(organization_id)
        if organization_id
          organization = Organizations::Organization.find_by_id(organization_id)
          return unless organization
        end

        current_time = Time.current
        over_time = false

        loop_with_runtime_limit(MAX_RUNTIME) do |runtime_limiter|
          batch = Analytics::CycleAnalytics::Aggregation.load_batch(current_time, :last_consistency_check_updated_at,
            organization: organization)
          break if batch.empty?

          batch.each do |aggregation|
            response = run_consistency_check_services(aggregation.namespace, runtime_limiter, cursor_data(aggregation))
            save_cursor_attrs!(aggregation, response, current_time)

            if limit_reached?(response) || runtime_limiter.over_time?
              over_time = true
              break
            end
          end

          break if over_time
        end
      end

      private

      def run_consistency_check_services(group, runtime_limiter, cursor_data)
        # Skip issues if the previous run stopped at merge requests,
        # as it means that issues were already processed
        unless cursor_data[:merge_requests_stage_event_hash_id].present?
          response = Analytics::CycleAnalytics::ConsistencyCheckService.new(
            namespace: group,
            event_model: Analytics::CycleAnalytics::IssueStageEvent
          ).execute(runtime_limiter: runtime_limiter, cursor_data: cursor_data)

          return response if limit_reached?(response)
        end

        Analytics::CycleAnalytics::ConsistencyCheckService.new(
          namespace: group,
          event_model: Analytics::CycleAnalytics::MergeRequestStageEvent
        ).execute(runtime_limiter: runtime_limiter, cursor_data: cursor_data)
      end

      def limit_reached?(service_response)
        service_response.payload[:reason] == :limit_reached
      end

      def save_cursor_attrs!(aggregation, service_response, current_time)
        # Reset all cursor attrs that are not explicitly set
        attrs = {
          last_consistency_check_issues_stage_event_hash_id: nil,
          last_consistency_check_issues_start_event_timestamp: nil,
          last_consistency_check_issues_end_event_timestamp: nil,
          last_consistency_check_issues_issuable_id: nil,
          last_consistency_check_merge_requests_stage_event_hash_id: nil,
          last_consistency_check_merge_requests_start_event_timestamp: nil,
          last_consistency_check_merge_requests_end_event_timestamp: nil,
          last_consistency_check_merge_requests_issuable_id: nil
        }

        if limit_reached?(service_response)
          attrs.merge!(cursor_attrs(service_response))
        else
          attrs[:last_consistency_check_updated_at] = current_time
        end

        aggregation.update!(attrs)
      end

      def cursor_attrs(service_response)
        payload = service_response.payload
        cursor = payload[:cursor]
        model = payload[:model]

        if model == ::Issue
          {
            last_consistency_check_issues_stage_event_hash_id: payload[:stage_event_hash_id],
            last_consistency_check_issues_start_event_timestamp: cursor['start_event_timestamp'],
            last_consistency_check_issues_end_event_timestamp: cursor['end_event_timestamp'],
            last_consistency_check_issues_issuable_id: cursor['issue_id']
          }
        elsif model == ::MergeRequest
          {
            last_consistency_check_merge_requests_stage_event_hash_id: payload[:stage_event_hash_id],
            last_consistency_check_merge_requests_start_event_timestamp: cursor['start_event_timestamp'],
            last_consistency_check_merge_requests_end_event_timestamp: cursor['end_event_timestamp'],
            last_consistency_check_merge_requests_issuable_id: cursor['merge_request_id']
          }
        else
          raise "invalid model #{model}"
        end
      end

      def cursor_data(aggregation)
        {
          issues_stage_event_hash_id: aggregation.last_consistency_check_issues_stage_event_hash_id,
          merge_requests_stage_event_hash_id: aggregation.last_consistency_check_merge_requests_stage_event_hash_id,
          issues_cursor: aggregation.consistency_check_cursor_for(Analytics::CycleAnalytics::IssueStageEvent),
          merge_requests_cursor: aggregation.consistency_check_cursor_for(Analytics::CycleAnalytics::MergeRequestStageEvent)
        }
      end
    end
  end
end
