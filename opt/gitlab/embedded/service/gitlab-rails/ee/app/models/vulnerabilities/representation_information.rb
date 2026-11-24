# frozen_string_literal: true

module Vulnerabilities
  class RepresentationInformation < ::SecApplicationRecord
    include ShaAttribute

    self.table_name = 'vulnerability_representation_information'
    self.primary_key = 'vulnerability_id'

    sha_attribute :resolved_in_commit_sha

    belongs_to :vulnerability
    belongs_to :project
    belongs_to :vulnerability_occurrence, optional: true, class_name: 'Vulnerabilities::Finding'

    scope :by_vulnerability, ->(vulnerability_ids) { where(vulnerability_id: vulnerability_ids) }

    validates :vulnerability, presence: true
    validates :project, presence: true
    validates :resolved_in_commit_sha, length: { maximum: 64 }
  end
end
