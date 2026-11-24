# frozen_string_literal: true

module EE
  module Gitlab
    module IssuableMetadata
      extend ::Gitlab::Utils::Override

      override :metadata_for_issuable
      def metadata_for_issuable(id)
        data = super

        # This block can be removed once we migrated all award_emojis from Epic to WorkItem
        if collection_type == 'Epic'
          epic = issuable_collection.find { |e| e.id == id }
          data.upvotes = unified_epic_upvotes(epic)
          data.downvotes = unified_epic_downvotes(epic)
        end

        if collection_type == 'Issue'
          blocking_count = grouped_blocking_issues_count.find { |issue| issue.blocking_issue_id == id }
          data.blocking_issues_count = blocking_count.try(:count).to_i
        end

        data
      end

      private

      def unified_epic_upvotes(epic)
        epic_vote = epic_votes.find { |v| v.awardable_id == epic.id && v.upvote? }
        work_item_vote = work_item_votes.find { |v| v.awardable_id == epic.issue_id && v.upvote? }
        epic_vote.try(:count).to_i + work_item_vote.try(:count).to_i
      end

      def unified_epic_downvotes(epic)
        epic_vote = epic_votes.find { |v| v.awardable_id == epic.id && v.downvote? }
        work_item_vote = work_item_votes.find { |v| v.awardable_id == epic.issue_id && v.downvote? }
        epic_vote.try(:count).to_i + work_item_vote.try(:count).to_i
      end

      def epic_votes
        strong_memoize(:epic_votes) do
          ::AwardEmoji.votes_for_collection(issuable_ids, 'Epic')
        end
      end

      def work_item_votes
        strong_memoize(:work_item_votes) do
          work_item_ids = issuable_collection.map(&:issue_id)
          ::AwardEmoji.votes_for_collection(work_item_ids, 'Issue')
        end
      end

      def grouped_blocking_issues_count
        strong_memoize(:grouped_blocking_issues_count) do
          ::IssueLink.blocking_issuables_for_collection(issuable_ids)
        end
      end
    end
  end
end
