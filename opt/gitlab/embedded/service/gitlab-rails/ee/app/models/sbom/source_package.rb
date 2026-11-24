# frozen_string_literal: true

module Sbom
  class SourcePackage < ::SecApplicationRecord
    has_many :occurrences, inverse_of: :source_package

    enum :purl_type, ::Enums::Sbom.purl_types

    belongs_to :organization, class_name: 'Organizations::Organization'

    scope :by_purl_type_and_name, ->(purl_type, name) do
      where(name: name, purl_type: purl_type)
    end
  end
end
