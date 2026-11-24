# frozen_string_literal: true

module Gitlab
  module Analytics
    module CycleAnalytics
      module StageEvents
        class MergeRequestLastApprovedAt < StageEvent
          def self.name
            s_("CycleAnalyticsEvent|Merge request last approved")
          end

          def self.identifier
            :merge_request_last_approved_at
          end

          def object_type
            MergeRequest
          end

          def column_list
            [mr_approval_metrics_table[:last_approved_at]]
          end

          # rubocop: disable CodeReuse/ActiveRecord -- context specific
          def apply_query_customization(query)
            super.joins(:approval_metrics)
          end
          # rubocop: enable CodeReuse/ActiveRecord

          def include_in(query, **)
            query.left_joins(:approval_metrics)
          end

          def apply_negated_query_customization(query)
            super.left_joins(:approval_metrics)
          end
        end
      end
    end
  end
end
