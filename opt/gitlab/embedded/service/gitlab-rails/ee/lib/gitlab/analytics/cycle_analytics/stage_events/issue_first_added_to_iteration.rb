# frozen_string_literal: true

module Gitlab
  module Analytics
    module CycleAnalytics
      module StageEvents
        class IssueFirstAddedToIteration < FirstResourceEventBase
          override :name
          def self.name
            s_("CycleAnalyticsEvent|Issue first added to iteration")
          end

          override :identifier
          def self.identifier
            :issue_first_added_to_iteration
          end

          override :object_type
          def object_type
            Issue
          end

          override :object_type
          def event_model
            ResourceIterationEvent
          end

          override :object_type
          def issuable_id_column
            event_model.arel_table[:issue_id]
          end
        end
      end
    end
  end
end
