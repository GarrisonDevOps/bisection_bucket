# frozen_string_literal: true

module Gitlab
  module ContributionAnalytics
    class DataFormatter
      attr_accessor :data

      def initialize(data)
        @data = data
      end

      # rubocop: disable CodeReuse/ActiveRecord
      def users(limit: 500, after_id: nil)
        author_ids = total_events_by_author_count.keys.sort
        author_ids = author_ids.drop_while { |id| id <= after_id } if after_id

        all_records = []
        author_ids.each_slice(limit) do |ids|
          records = User
            .active
            .select(:id, :name, :username)
            .id_in(ids)
            .reorder(:id)
            .to_a

          all_records.concat(records)
          break if all_records.size >= limit
        end

        all_records.take(limit)
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def totals
        @totals ||= {
          push: push_by_author_count,
          issues_created: issues_created_by_author_count,
          issues_closed: issues_closed_by_author_count,
          merge_requests_closed: merge_requests_closed_by_author_count,
          merge_requests_created: merge_requests_created_by_author_count,
          merge_requests_merged: merge_requests_merged_by_author_count,
          merge_requests_approved: merge_requests_approved_by_author_count,
          total_events: total_events_by_author_count
        }
      end

      private

      def push_by_author_count
        data.each_with_object({}) do |(event, count), hash|
          hash[event.author_id] = count if event.target_type.nil? && event.pushed_action?
        end
      end

      def issues_created_by_author_count
        data.each_with_object({}) do |(event, count), hash|
          hash[event.author_id] = count if event.issue? && event.created_action?
        end
      end

      def issues_closed_by_author_count
        data.each_with_object({}) do |(event, count), hash|
          hash[event.author_id] = count if event.issue? && event.closed_action?
        end
      end

      def merge_requests_closed_by_author_count
        data.each_with_object({}) do |(event, count), hash|
          hash[event.author_id] = count if event.merge_request? && event.closed_action?
        end
      end

      def merge_requests_created_by_author_count
        data.each_with_object({}) do |(event, count), hash|
          hash[event.author_id] = count if event.merge_request? && event.created_action?
        end
      end

      def merge_requests_merged_by_author_count
        data.each_with_object({}) do |(event, count), hash|
          hash[event.author_id] = count if event.merge_request? && event.merged_action?
        end
      end

      def merge_requests_approved_by_author_count
        data.each_with_object({}) do |(event, count), hash|
          hash[event.author_id] = count if event.merge_request? && event.approved_action?
        end
      end

      def total_events_by_author_count
        data.each_with_object({}) do |(event, count), hash|
          hash[event.author_id] ||= 0
          hash[event.author_id] += count
        end
      end
    end
  end
end
