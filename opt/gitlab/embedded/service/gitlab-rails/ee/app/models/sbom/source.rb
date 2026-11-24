# frozen_string_literal: true

module Sbom
  class Source < ::SecApplicationRecord
    include ::Sbom::SourceHelper

    DEFAULT_SOURCES = {
      dependency_scanning: 0,
      container_scanning: 1
    }.freeze

    enum :source_type, {
      container_scanning_for_registry: 2
    }.merge(DEFAULT_SOURCES)

    belongs_to :organization, class_name: 'Organizations::Organization'
    has_many :occurrences, inverse_of: :source

    validates :source_type, presence: true
    validates :source, presence: true, json_schema: { filename: 'sbom_source' }

    alias_attribute :data, :source
  end
end
