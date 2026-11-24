# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      # Classification of a finding Duo Code Review posted as a diff note. Only the
      # review publish step writes these rows, and each one lives as long as its note.
      class Finding < ::ApplicationRecord
        self.table_name = :duo_code_review_findings
        self.primary_key = :note_id

        CATEGORY_MAX_LENGTH = 255
        CONFIDENCE_RANGE = (0..10)

        belongs_to :note, optional: false, inverse_of: :duo_code_review_finding
        belongs_to :project, optional: false
        belongs_to :merge_request, optional: false
        belongs_to :workflow, class_name: 'Ai::DuoWorkflows::Workflow', optional: true,
          inverse_of: :code_review_findings

        enum :severity, { critical: 1, major: 2, minor: 3 }
        enum :depth, { lite: 1, standard: 2 }, prefix: true

        validates :severity, :depth, presence: true
        validates :category, presence: true, length: { maximum: CATEGORY_MAX_LENGTH }
        validates :confidence, numericality: { only_integer: true, in: CONFIDENCE_RANGE }, allow_nil: true

        populate_sharding_key :project_id, source: :merge_request
      end
    end
  end
end
