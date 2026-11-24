# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      class Integration < ApplicationRecord
        self.table_name = 'ai_compliance_anthropic_integrations'

        # Set only when GitLab disables the integration itself. A nil value with
        # enabled false means the owner turned it off, or it was never on.
        enum :disabled_reason, {
          invalid_key: 0,
          local_sessions_unavailable: 1,
          repeated_failures: 2
        }, prefix: true

        encrypts :api_key

        belongs_to :namespace, class_name: '::Group', optional: false

        validates :api_key, presence: true, length: { maximum: 510 }
        validates :namespace_id, uniqueness: true
        validates :anthropic_organization_uuid, length: { maximum: 255 }
        validates :list_cursor, length: { maximum: 2048 }
        validates :last_error, length: { maximum: 1024 }

        validate :validate_root_namespace

        scope :enabled, -> { where(enabled: true) }
        scope :for_namespaces, ->(namespace_ids) { where(namespace_id: namespace_ids) }
        scope :including_namespace_route, -> { preload(namespace: :route) }

        private

        def validate_root_namespace
          return if namespace.nil? || namespace.root?

          errors.add(:namespace, 'must be a top-level group.')
        end
      end
    end
  end
end
