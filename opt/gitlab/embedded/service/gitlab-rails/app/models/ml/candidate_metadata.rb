# frozen_string_literal: true

module Ml
  class CandidateMetadata < ApplicationRecord
    validates :candidate, presence: true
    validates :name,
      length: { maximum: 250 },
      presence: true,
      uniqueness: { scope: :candidate, message: ->(candidate, _) { "'#{candidate.name}' already taken" } }
    validates :value, length: { maximum: 5000 }, presence: true

    belongs_to :candidate, class_name: 'Ml::Candidate'

    scope :for_candidates, ->(candidates) { where(candidate_id: candidates.select(:id)) }
  end
end
