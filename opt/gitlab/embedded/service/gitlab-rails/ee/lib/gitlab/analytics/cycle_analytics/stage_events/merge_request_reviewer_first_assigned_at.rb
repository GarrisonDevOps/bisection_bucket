# frozen_string_literal: true

module Gitlab
  module Analytics
    module CycleAnalytics
      module StageEvents
        class MergeRequestReviewerFirstAssignedAt < MetricsBasedStageEvent
          def self.name
            s_("CycleAnalyticsEvent|Merge request reviewer first assigned")
          end

          def self.identifier
            :merge_request_reviewer_first_assigned
          end

          def object_type
            MergeRequest
          end

          def column_list
            [mr_metrics_table[:reviewer_first_assigned_at]]
          end
        end
      end
    end
  end
end
