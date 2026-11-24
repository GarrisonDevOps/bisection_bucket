# frozen_string_literal: true

module EE
  module Gitlab
    module Analytics
      module CycleAnalytics
        module StageEvents
          extend ActiveSupport::Concern

          prepended do
            extend ::Gitlab::Utils::StrongMemoize
          end

          def self.event(klass)
            const_get("::Gitlab::Analytics::CycleAnalytics::StageEvents::#{klass.to_s.classify}", false)
          end

          def self.events(*all_events)
            all_events.map { |e| event(e) }.freeze
          end

          EE_ENUM_MAPPING = {
            event(:issue_closed) => 3,
            event(:issue_first_added_to_board) => 4,
            event(:issue_first_associated_with_milestone) => 5,
            event(:issue_last_edited) => 7,
            event(:issue_label_added) => 8,
            event(:issue_label_removed) => 9,
            event(:issue_first_assigned_at) => 11,
            event(:issue_first_added_to_iteration) => 12,
            event(:merge_request_closed) => 105,
            event(:merge_request_last_edited) => 106,
            event(:merge_request_label_added) => 107,
            event(:merge_request_label_removed) => 108,
            event(:merge_request_first_commit_at) => 109,
            event(:merge_request_first_assigned_at) => 110,
            event(:merge_request_reviewer_first_assigned_at) => 111,
            event(:merge_request_last_approved_at) => 112
          }.freeze

          EE_EVENTS = EE_ENUM_MAPPING.keys.freeze

          EE_PAIRING_RULES = {
            event(:issue_label_added) => events(
              :issue_label_added,
              :issue_label_removed,
              :issue_closed,
              :issue_first_assigned_at,
              :issue_first_added_to_iteration
            ),
            event(:issue_label_removed) => events(
              :issue_closed,
              :issue_first_assigned_at,
              :issue_first_added_to_iteration
            ),
            event(:issue_created) => events(
              :issue_closed,
              :issue_first_added_to_board,
              :issue_first_associated_with_milestone,
              :issue_first_mentioned_in_commit,
              :issue_last_edited,
              :issue_label_added,
              :issue_label_removed,
              :issue_first_assigned_at,
              :issue_first_added_to_iteration
            ),
            event(:issue_first_added_to_board) => events(
              :issue_closed,
              :issue_first_associated_with_milestone,
              :issue_first_mentioned_in_commit,
              :issue_last_edited,
              :issue_label_added,
              :issue_label_removed,
              :issue_first_assigned_at,
              :issue_first_added_to_iteration
            ),
            event(:issue_first_associated_with_milestone) => events(
              :issue_closed,
              :issue_first_added_to_board,
              :issue_first_mentioned_in_commit,
              :issue_last_edited,
              :issue_label_added,
              :issue_label_removed,
              :issue_first_assigned_at,
              :issue_first_added_to_iteration
            ),
            event(:issue_first_mentioned_in_commit) => events(
              :issue_closed,
              :issue_first_associated_with_milestone,
              :issue_first_added_to_board,
              :issue_last_edited,
              :issue_label_added,
              :issue_label_removed,
              :issue_first_assigned_at,
              :issue_first_added_to_iteration
            ),
            event(:issue_closed) => events(
              :issue_last_edited,
              :issue_label_added,
              :issue_label_removed
            ),
            event(:issue_first_assigned_at) => events(
              :issue_closed,
              :issue_first_added_to_board,
              :issue_first_associated_with_milestone,
              :issue_first_mentioned_in_commit,
              :issue_last_edited,
              :issue_label_added,
              :issue_label_removed,
              :issue_first_added_to_iteration
            ),
            event(:issue_first_added_to_iteration) => events(
              :issue_closed,
              :issue_first_added_to_board,
              :issue_first_associated_with_milestone,
              :issue_first_mentioned_in_commit,
              :issue_last_edited,
              :issue_label_added,
              :issue_label_removed,
              :issue_first_assigned_at
            ),
            event(:merge_request_first_commit_at) => events(
              :merge_request_closed,
              :merge_request_first_deployed_to_production,
              :merge_request_last_build_started,
              :merge_request_last_build_finished,
              :merge_request_last_edited,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_merged,
              :merge_request_first_assigned_at,
              :merge_request_reviewer_first_assigned_at,
              :merge_request_last_approved_at
            ),
            event(:merge_request_created) => events(
              :merge_request_closed,
              :merge_request_first_deployed_to_production,
              :merge_request_last_build_started,
              :merge_request_last_build_finished,
              :merge_request_last_edited,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_first_assigned_at,
              :merge_request_reviewer_first_assigned_at,
              :merge_request_last_approved_at
            ),
            event(:merge_request_closed) => events(
              :merge_request_first_deployed_to_production,
              :merge_request_last_edited,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_first_commit_at
            ),
            event(:merge_request_first_deployed_to_production) => events(
              :merge_request_last_edited,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_first_commit_at,
              :merge_request_last_approved_at
            ),
            event(:merge_request_last_build_started) => events(
              :merge_request_closed,
              :merge_request_first_deployed_to_production,
              :merge_request_last_edited,
              :merge_request_merged,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_first_commit_at,
              :merge_request_reviewer_first_assigned_at
            ),
            event(:merge_request_last_build_finished) => events(
              :merge_request_closed,
              :merge_request_first_deployed_to_production,
              :merge_request_last_edited,
              :merge_request_merged,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_first_commit_at,
              :merge_request_reviewer_first_assigned_at
            ),
            event(:merge_request_merged) => events(
              :merge_request_closed,
              :merge_request_first_deployed_to_production,
              :merge_request_last_edited,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_first_commit_at
            ),
            event(:merge_request_label_added) => events(
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_merged,
              :merge_request_first_assigned_at,
              :merge_request_reviewer_first_assigned_at,
              :merge_request_last_approved_at
            ),
            event(:merge_request_label_removed) => events(
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_first_assigned_at,
              :merge_request_reviewer_first_assigned_at,
              :merge_request_last_approved_at
            ),
            event(:merge_request_first_assigned_at) => events(
              :merge_request_closed,
              :merge_request_last_build_started,
              :merge_request_first_deployed_to_production,
              :merge_request_last_edited,
              :merge_request_merged,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_reviewer_first_assigned_at,
              :merge_request_last_approved_at
            ),
            event(:merge_request_reviewer_first_assigned_at) => events(
              :merge_request_closed,
              :merge_request_last_build_started,
              :merge_request_first_deployed_to_production,
              :merge_request_last_edited,
              :merge_request_merged,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_last_approved_at
            ),
            event(:merge_request_last_approved_at) => events(
              :merge_request_merged,
              :merge_request_closed,
              :merge_request_last_edited,
              :merge_request_label_added,
              :merge_request_label_removed,
              :merge_request_last_build_started,
              :merge_request_last_build_finished
            )
          }.freeze

          class_methods do
            extend ::Gitlab::Utils::Override

            override :events
            def events
              strong_memoize(:events) do
                (super + EE_EVENTS)
              end
            end

            override :pairing_rules
            def pairing_rules
              strong_memoize(:pairing_rules) do
                # merging two hashes with array values
                ::Gitlab::Analytics::CycleAnalytics::StageEvents::PAIRING_RULES.merge(EE_PAIRING_RULES) do |klass, foss_events, ee_events|
                  foss_events + ee_events
                end
              end
            end

            override :enum_mapping
            def enum_mapping
              strong_memoize(:enum_mapping) do
                super.merge(EE_ENUM_MAPPING)
              end
            end
          end
        end
      end
    end
  end
end
