# frozen_string_literal: true

module Ml
  # Tag rows (name and value pairs) are created many at a time. `bulk_create!` validates
  # each record like `create!` does, with one uniqueness query for the whole batch instead
  # of one per record, and then inserts all records in one statement.
  module BulkInsertableMetadata
    extend ActiveSupport::Concern

    TAKEN_MESSAGE = ->(metadata, _) { "'#{metadata.name}' already taken" }

    included do
      # Names already used for the parent. Set by `bulk_create!` to skip the per-record uniqueness query.
      attr_accessor :taken_names
    end

    class_methods do
      def bulk_create!(records, existing:)
        names = records.map(&:name)
        taken_names = existing.where(name: names).limit(names.size).pluck(:name).to_set

        rows = records.map do |record|
          record.taken_names = taken_names
          record.validate!
          taken_names << record.name

          record.attributes.except('id', 'created_at', 'updated_at')
        end

        insert_all!(rows, returning: false)
      end
    end

    private

    def name_not_taken
      errors.add(:name, :taken, message: TAKEN_MESSAGE) if taken_names.include?(name)
    end
  end
end
