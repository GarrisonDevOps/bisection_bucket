# frozen_string_literal: true

module EE
  module Gitlab
    module HookData
      module MergeRequestBuilder
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        EE_SAFE_HOOK_ATTRIBUTES = %i[
          approval_rules
        ].freeze

        override :build
        def build
          attrs = super

          if merge_request.supports_approval_rules?
            attrs[:approval_rules] = merge_request.approval_rules.map(&:hook_attrs)
          end

          attrs.merge!(line_count_attributes)
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :safe_hook_attributes
          def safe_hook_attributes
            super + EE_SAFE_HOOK_ATTRIBUTES
          end
        end

        private

        # Line counts are stored on merge only, so they are nil before that. Named
        # changed_lines, not changes like GraphQL, to avoid clashing with the
        # top-level changes object of the payload.
        def line_count_attributes
          added_lines = merge_request.metrics&.added_lines
          deleted_lines = merge_request.metrics&.removed_lines

          {
            added_lines: added_lines,
            deleted_lines: deleted_lines,
            changed_lines: (added_lines + deleted_lines if added_lines && deleted_lines)
          }
        end
      end
    end
  end
end
