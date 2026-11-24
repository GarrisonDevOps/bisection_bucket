# frozen_string_literal: true

module Resolvers
  module Vulnerabilities
    class DetailsResolver < BaseResolver
      include ::Vulnerabilities::DetailSanitizer

      type [::Types::VulnerabilityDetailType], null: false

      def resolve
        return [] if object.respond_to?(:finding) && object.finding&.secret_redacted?

        # This function can be called from two different places, each providing 'object' in a different format:
        # 1. From the database: 'object' instance with a 'finding_details' method.
        # 2. From an artifact: 'object' is a hash-like structure with a 'details' key.
        details = if object.respond_to?(:finding_details)
                    object.finding_details
                  elsif object.is_a?(Hash) && object.key?('details')
                    object['details']
                  end

        return [] if details.blank?

        self.class.with_field_name(details.with_indifferent_access).map { |detail| sanitize_detail(detail) }
      end

      def self.with_field_name(items)
        return [] if items.blank?

        items.map { |field_name, field| field.merge(field_name: field_name) }
      end
    end
  end
end
