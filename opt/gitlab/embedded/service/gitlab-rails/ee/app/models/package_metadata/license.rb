# frozen_string_literal: true

module PackageMetadata
  class License < ApplicationRecord
    include BulkInsertSafe

    validates :spdx_identifier, length: { maximum: 50 }, allow_nil: true
    validates :spdx_expression, length: { maximum: 1024 }, allow_nil: true
    validate :exactly_one_of_identifier_or_expression

    scope :with_spdx_identifiers, ->(spdx_identifiers) do
      where(spdx_identifier: spdx_identifiers)
    end

    scope :with_spdx_expressions, ->(spdx_expressions) do
      where(spdx_expression: spdx_expressions)
    end

    scope :select_id_and_spdx_values, -> { select(:id, :spdx_identifier, :spdx_expression) }

    private

    def exactly_one_of_identifier_or_expression
      return if [spdx_identifier.present?, spdx_expression.present?].one?

      errors.add(:base, 'exactly one of spdx_identifier or spdx_expression must be present')
    end
  end
end
