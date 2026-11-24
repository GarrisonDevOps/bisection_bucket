# frozen_string_literal: true

module Ml
  class CandidateMetric < ApplicationRecord
    validates :candidate, presence: true
    validates :name, length: { maximum: 250 }, presence: true

    belongs_to :candidate, class_name: 'Ml::Candidate'

    scope :for_candidates, ->(candidates) { where(candidate_id: candidates.select(:id)) }
    scope :latest, -> { select('DISTINCT ON (candidate_id, name) *').order('candidate_id, name, id DESC') }
    scope :for_history, ->(candidate_id, metric_name) {
      where(candidate_id: candidate_id, name: metric_name)
        .order(step: :asc, tracked_at: :asc)
    }

    # OFFSET 0 keeps the candidate_id index: with ORDER BY id alone, PostgreSQL can scan the whole primary key.
    scope :most_recent_for_candidate, ->(candidate_id, limit) {
      from(where(candidate_id: candidate_id).offset(0), :ml_candidate_metrics)
        .order(id: :desc)
        .limit(limit)
    }
  end
end
