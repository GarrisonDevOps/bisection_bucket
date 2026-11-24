# frozen_string_literal: true

module EE
  module MergeRequestMetricsService
    extend ::Gitlab::Utils::Override

    delegate :merge_request, to: :@merge_request_metrics

    # rubocop:disable Gitlab/ModuleWithInstanceVariables -- simple memoization: prepared in prepare_merge_data, reused by merge
    # Reads every commit and diff file of the merge request from Gitaly, so run
    # it outside the transaction #merge is called in.
    override :prepare_merge_data
    def prepare_merge_data
      @calculated_merge_data = calculated_merge_data
    rescue ActiveRecord::QueryCanceled => e # rubocop:disable Database/RescueQueryCanceled -- analytics-only data; a timeout computing it must not prevent the merge state and event from being recorded
      ::Gitlab::ErrorTracking.track_exception(
        e,
        { merge_request_id: merge_request.id, project_id: merge_request.target_project_id },
        { merged_manually_detection: 'productivity_metrics_fallback' }
      )

      @calculated_merge_data = {}
    end

    override :merge
    def merge(event)
      data = {
        merged_by_id: event.author_id,
        merged_at: event.created_at
      }.merge(@calculated_merge_data || calculated_merge_data)

      update!(data)
    end
    # rubocop:enable Gitlab/ModuleWithInstanceVariables

    private

    def calculated_merge_data
      metrics_calculator.productivity_data.merge(metrics_calculator.line_counts_data)
    end

    def metrics_calculator
      @metrics_calculator ||= ::Analytics::MergeRequestMetricsCalculator.new(merge_request)
    end
  end
end
