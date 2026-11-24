# frozen_string_literal: true

module Search
  module Zoekt
    module NamespaceValidateable
      extend ActiveSupport::Concern

      included do
        validate :zoekt_enabled_root_namespace_matches_namespace_id

        private

        def zoekt_enabled_root_namespace_matches_namespace_id
          return unless zoekt_enabled_namespace.present? && namespace_id.present?
          return if zoekt_enabled_namespace.root_namespace_id == namespace_id

          errors.add(:namespace_id, :invalid)
        end
      end
    end
  end
end
