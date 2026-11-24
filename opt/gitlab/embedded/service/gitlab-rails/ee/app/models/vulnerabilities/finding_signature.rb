# frozen_string_literal: true

module Vulnerabilities
  class FindingSignature < ::SecApplicationRecord
    include BulkInsertSafe
    include VulnerabilityFindingSignatureHelpers

    self.table_name = 'vulnerability_finding_signatures'

    belongs_to :finding, inverse_of: :signatures, class_name: 'Vulnerabilities::Finding'

    enum :algorithm_type, VulnerabilityFindingSignatureHelpers::ALGORITHM_TYPES, prefix: :algorithm

    validates :finding, presence: true
    validates :signature_sha, presence: true, length: { maximum: 40 }

    scope :by_project, ->(project) { joins(:finding).where(vulnerability_occurrences: { project_id: project.id }) }
    scope :by_signature_sha, ->(shas) { where(signature_sha: shas) }
    scope :by_finding_id, ->(finding_ids) { where(finding: finding_ids) }
    scope :eager_load_comparison_entities, -> {
      includes(finding: [:scanner, :primary_identifier, :project_tracked_context])
    }

    def signature_hex
      Digest::SHA1.hexdigest(hex_content) # rubocop:disable Fips/SHA1 -- Callers of this method expects 20 bytes hexadecimal value
    end

    def eql?(other)
      other.is_a?(self.class) &&
        other.algorithm_type == algorithm_type &&
        other.signature_sha == signature_sha
    end

    alias_method :==, :eql?

    def hex_content
      "#{algorithm_type}:#{signature_sha.unpack1('H*')}"
    end
  end
end
