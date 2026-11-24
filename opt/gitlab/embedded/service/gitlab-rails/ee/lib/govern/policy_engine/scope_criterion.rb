# frozen_string_literal: true

module Govern
  module PolicyEngine
    # The store sends the policy_scope lists as plain JSON, and only this
    # class reads their shape. The rest of the code works with ids and types.
    class ScopeCriterion
      ID = 'id'
      TYPE = 'type'

      # Same bounds as the store's ScopeTranspiler, which coerces "42" to 42
      # when it compiles the document. Resolving an entry differently here
      # would hide a project from the sweep that the compiled Rego matches.
      MAX_ID = (2**63) - 1
      MAX_ID_LENGTH = MAX_ID.to_s.length + 1

      def self.from(raw)
        new(raw.is_a?(Array) ? raw : [])
      end

      def initialize(entries)
        @entries = entries
      end

      # An entry that coerces to no usable id names no record.
      def ids
        entries.filter_map { |entry| id_of(entry) }
      end

      def includes_type?(type)
        entries.any? { |entry| entry.is_a?(Hash) && entry[TYPE] == type }
      end

      private

      attr_reader :entries

      def id_of(entry)
        value = entry.is_a?(Hash) ? entry[ID] : entry
        id = coerced_id(value)

        id if id && id > 0 && id <= MAX_ID
      end

      def coerced_id(value)
        case value
        when Integer then value
        when String then value.to_i if integer_text?(value)
        end
      end

      def integer_text?(value)
        value.length <= MAX_ID_LENGTH &&
          value.encoding.ascii_compatible? && value.valid_encoding? && value.match?(/\A-?\d+\z/)
      end
    end
  end
end
