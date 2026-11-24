# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Hierarchy < Grape::Entity
          expose :parent,
            using: ::API::Entities::WorkItems::Features::HierarchyParent,
            expose_nil: true,
            documentation: {
              type: 'Entities::WorkItems::Features::HierarchyParent',
              desc: 'Parent of the work item. Null if the work item has no parent, or if the current user ' \
                'cannot view the parent.'
            } do |feature, options|
            parent = feature.parent
            next unless parent && Ability.allowed?(options[:current_user], :read_work_item, parent)

            parent
          end

          expose :has_parent,
            documentation: {
              type: 'Boolean', example: false,
              desc: 'Whether the work item has a parent. Can be `true` even if the current user cannot view the parent.'
            } do |feature|
            feature.parent.present?
          end
        end
      end
    end
  end
end
