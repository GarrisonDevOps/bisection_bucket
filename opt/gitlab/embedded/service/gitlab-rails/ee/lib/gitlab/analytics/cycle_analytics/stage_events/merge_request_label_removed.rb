# frozen_string_literal: true

module Gitlab
  module Analytics
    module CycleAnalytics
      module StageEvents
        class MergeRequestLabelRemoved < LabelBasedStageEvent
          def self.name
            s_("CycleAnalyticsEvent|Merge request label removed")
          end

          def self.identifier
            :merge_request_label_removed
          end

          def html_description(options)
            s_("CycleAnalyticsEvent|%{label_reference} label was removed from the merge request") % { label_reference: options.fetch(:label_html) }
          end

          def object_type
            MergeRequest
          end

          def subquery(include_all_timestamps_as_array: false)
            resource_label_events_with_subquery(:merge_request_id, label, ::ResourceLabelEvent.actions[:remove], :desc, include_all_timestamps_as_array: include_all_timestamps_as_array)
          end
        end
      end
    end
  end
end
