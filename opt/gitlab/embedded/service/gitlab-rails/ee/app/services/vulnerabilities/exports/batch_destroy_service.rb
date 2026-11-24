# frozen_string_literal: true

module Vulnerabilities
  module Exports
    class BatchDestroyService
      include BaseServiceUtility
      include Gitlab::HandlesRemovalOf

      handles_removal_of :vulnerability_export_parts

      def initialize(exports:)
        @exports = exports
      end

      def execute
        return if exports.blank?

        exports.each_batch do |batch|
          destroy_export_parts_for(batch)

          batch.tap { |exports| Upload.destroy_for_associations!(exports) }
               .delete_all
        end
      end

      private

      attr_reader :exports, :only_expired

      # The parts cascade away with their export, which drops the rows without
      # their uploads and leaves orphans that fail Geo verification.
      def destroy_export_parts_for(batch)
        Vulnerabilities::Export::Part.for_exports(batch).each_batch do |parts|
          parts.tap { |records| Upload.destroy_for_associations!(records) }
               .delete_all
        end
      end
    end
  end
end
