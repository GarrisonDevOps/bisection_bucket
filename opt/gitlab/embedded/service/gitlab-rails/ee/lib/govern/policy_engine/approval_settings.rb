# frozen_string_literal: true

module Govern
  module PolicyEngine
    # The approval settings whose project column carries another name, and
    # sometimes the opposite value. The catalog allows what the column
    # disables. ProjectSettingsContext reads the column through this table.
    class ApprovalSettings
      Entry = Data.define(:setting, :column, :inverted) do
        alias_method :inverted?, :inverted

        # Negation is its own inverse, so one method serves both directions.
        def convert(value)
          cast = ActiveModel::Type::Boolean.new.cast(value)

          inverted? ? !cast : cast
        end
      end

      ENTRIES = [
        Entry.new(setting: 'allow_author_approval',
          column: :merge_requests_author_approval, inverted: false),
        Entry.new(setting: 'allow_committer_approval',
          column: :merge_requests_disable_committers_approval, inverted: true),
        Entry.new(setting: 'allow_overrides_to_approver_list_per_merge_request',
          column: :disable_overriding_approvers_per_merge_request, inverted: true),
        Entry.new(setting: 'retain_approvals_on_push',
          column: :reset_approvals_on_push, inverted: true)
      ].freeze

      BY_SETTING = ENTRIES.index_by(&:setting).freeze
      BY_COLUMN = ENTRIES.index_by { |entry| entry.column.to_s }.freeze

      def self.by_setting(setting)
        BY_SETTING[setting]
      end

      def self.by_column(column)
        BY_COLUMN[column.to_s]
      end

      def self.settings
        BY_SETTING.keys
      end

      def self.columns
        BY_COLUMN.keys
      end
    end
  end
end
