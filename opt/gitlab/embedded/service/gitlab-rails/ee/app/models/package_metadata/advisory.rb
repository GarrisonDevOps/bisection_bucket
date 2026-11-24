# frozen_string_literal: true

module PackageMetadata
  class Advisory < ApplicationRecord
    include Gitlab::Utils::StrongMemoize

    MAX_URL_SIZE = 512
    CVE_REGEX = /\ACVE-\d{4}-\d{4,15}\z/

    has_many :affected_packages, inverse_of: :advisory, foreign_key: :pm_advisory_id

    # the position of this line is important - it needs to be after the has_many declaration
    include BulkInsertSafe

    enum :source_xid, ::Enums::PackageMetadata.advisory_sources

    attribute :cvss_v2, Gitlab::Database::Type::CvssVector.new
    attribute :cvss_v3, Gitlab::Database::Type::CvssVector.new
    attribute :cvss_v4, Gitlab::Database::Type::CvssVector.new

    validates :advisory_xid, presence: true, length: { maximum: 36 }
    validates :source_xid, presence: true
    validates :published_date, presence: true
    validates :title, length: { maximum: 256 }
    validates :description, length: { maximum: 8192 }
    validates :cvss_v2, 'vulnerabilities/cvss_vector': { allowed_versions: [2] }, if: -> { cvss_v2.present? }
    validates :cvss_v3, 'vulnerabilities/cvss_vector': { allowed_versions: [3.0, 3.1] }, if: -> { cvss_v3.present? }
    validates :cvss_v4, 'vulnerabilities/cvss_vector': { allowed_versions: [4.0] }, if: -> { cvss_v4.present? }
    validates :identifiers, json_schema: { filename: 'pm_advisory_identifiers' }
    validates :urls, length: { minimum: 0, maximum: 20 }
    validates_each :urls do |record, _, urls|
      urls.each do |url|
        record.errors.add(url, "size is greater than #{MAX_URL_SIZE}") if url.size > MAX_URL_SIZE
      end
    end
    validates :cve, format: { with: CVE_REGEX }, allow_nil: true

    scope :with_affected_packages, -> { includes(:affected_packages) }
    scope :ordered_by_id, -> { order(id: :asc) }
    scope :by_identifiers, ->(identifiers) {
      return none if identifiers.blank?

      conditions = identifiers.map { "identifiers @> ?" }.join(" OR ")
      values = identifiers.map { |id| [{ name: id.to_s }].to_json }
      where(conditions, *values)
    }
    scope :created_after, ->(date) { where('created_at > ?', date) }
    scope :updated_after, ->(date) { where('updated_at > ?', date) }

    def self.find_by_identifier(identifier)
      by_identifiers(Array(identifier)).first
    end

    def from_container_scanning?
      source_xid == 'trivy-db'
    end
  end
end
