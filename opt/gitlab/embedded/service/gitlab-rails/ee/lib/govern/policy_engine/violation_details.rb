# frozen_string_literal: true

module Govern
  module PolicyEngine
    # The violations one decision reports, in the form the audit trail and
    # the stored evaluation both record. Each one holds the engine's own
    # details plus the reason message that came with it.
    class ViolationDetails
      # The engine reports violations as plain hashes, so the key names of one
      # violation detail appear here only.
      MESSAGE_KEY = 'message'
      PATH_KEY = 'path'
      EXPECTED_KEY = 'expected'
      ACTUAL_KEY = 'actual'

      def self.from_decision(decision)
        return new([]) unless decision[:matched]

        new(decision[:reasons].to_a.map { |reason| detail_for(reason) })
      end

      def self.detail_for(reason)
        details = reason[:details].is_a?(Hash) ? reason[:details] : {}

        details.merge(MESSAGE_KEY => reason[:message]).compact
      end
      private_class_method :detail_for

      def initialize(details)
        @details = details
      end

      def to_a
        @details
      end

      def settings
        @details.filter_map { |detail| detail[PATH_KEY] }
      end

      def joined_settings
        settings.join(',')
      end
    end
  end
end
