# frozen_string_literal: true

module Ai
  module FeatureAccessRuleable
    extend ActiveSupport::Concern

    included do
      include BulkInsertSafe

      validates :accessible_entity, presence: true
      validates :accessible_entity,
        length: { maximum: 255 },
        inclusion: { in: %w[duo_classic duo_agent_platform] }
      validates :accessible_entity, uniqueness: { scope: [:through_namespace_id] },
        if: -> { through_namespace_id.present? }

      alias_attribute :feature, :accessible_entity
    end
  end
end
