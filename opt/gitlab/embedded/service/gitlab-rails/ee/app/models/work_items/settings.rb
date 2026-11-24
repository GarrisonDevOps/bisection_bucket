# frozen_string_literal: true

module WorkItems
  class Settings < ApplicationRecord
    self.table_name = 'work_item_settings'

    belongs_to :organization, class_name: 'Organizations::Organization', optional: true
    belongs_to :namespace, optional: true

    validates :customizable_type_visibility, inclusion: { in: [true, false] }
    validates :organization_id, uniqueness: true, allow_nil: true
    validates :namespace_id, uniqueness: true, allow_nil: true
    validates_with ExactlyOnePresentValidator, fields: :sharding_keys

    class << self
      def for_namespace(namespace)
        return unless namespace

        if namespace.is_a?(::Organizations::Organization)
          find_or_initialize_by(organization_id: namespace.id)
        elsif ::Gitlab::Saas.feature_available?(:namespace_scoped_work_item_types)
          find_or_initialize_by(namespace_id: namespace.root_ancestor.id)
        else
          find_or_initialize_by(organization_id: namespace.organization_id)
        end
      end
    end

    private

    def sharding_keys
      [:namespace_id, :organization_id]
    end
  end
end
