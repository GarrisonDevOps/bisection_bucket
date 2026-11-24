# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module RecommendReviewers
        # Counts each approver's open review requests. Reviews they have already responded to still need
        # follow-up, so those count for half.
        class ReviewerWorkload
          include Gitlab::Utils::StrongMemoize

          PENDING_REVIEW_STATES = %w[unapproved unreviewed review_started].freeze
          RESPONDED_REVIEW_WEIGHT = 0.5
          # Review requests older than this no longer count as workload.
          WORKLOAD_WINDOW = 15.days

          # users holds every approver whose workload can be asked for.
          def initialize(users)
            @users_by_id = users.index_by(&:id)
          end

          def pending_reviews(user)
            windowed_review_counts[user.id][:pending]
          end

          def responded_reviews_weights(user_ids)
            user_ids.index_with { |id| responded_weight(windowed_review_counts[id][:responded]) }
          end

          private

          attr_reader :users_by_id

          # One query for every approver instead of a count each. The window keeps it on
          # `index_merge_request_reviewers_on_user_id_and_created_at`, so it needs no cache or Sidekiq guard.
          def windowed_review_counts
            counts = Hash.new { |hash, id| hash[id] = { pending: 0, responded: 0 } }

            MergeRequestReviewer
              .joins(merge_request: :target_project)
              .merge(MergeRequest.opened)
              .where(projects: { archived: false })
              .where(user_id: users_by_id.keys, created_at: WORKLOAD_WINDOW.ago..)
              .group(:user_id, :state)
              .count
              .each do |(user_id, state), count|
                counts[user_id][PENDING_REVIEW_STATES.include?(state) ? :pending : :responded] += count
              end

            counts
          end
          strong_memoize_attr :windowed_review_counts

          def responded_weight(count)
            (count.to_i * RESPONDED_REVIEW_WEIGHT).round
          end
        end
      end
    end
  end
end
