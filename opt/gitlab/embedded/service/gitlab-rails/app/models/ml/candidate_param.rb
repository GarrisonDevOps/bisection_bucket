# frozen_string_literal: true

module Ml
  class CandidateParam < ApplicationRecord
    validates :candidate, presence: true
    validates :name, uniqueness: { scope: :candidate }
    validates :name, :value, length: { maximum: 250 }, presence: true

    belongs_to :candidate, class_name: 'Ml::Candidate'

    scope :for_candidates, ->(candidates) { where(candidate_id: candidates.select(:id)) }
  end
end
