# frozen_string_literal: true

module EE
  module WorkItems
    module ParentLinks
      module BaseService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        def initialize(issuable, user, params)
          @synced_work_item = params.delete(:synced_work_item)

          super
        end

        override :linkable?
        def linkable?(work_item)
          return true if synced_work_item
          return true if work_item.importing?
          return false if work_item.work_item_type.epic? && !work_item.namespace.licensed_feature_available?(:subepics)

          super
        end

        private

        attr_reader :synced_work_item
      end
    end
  end
end
