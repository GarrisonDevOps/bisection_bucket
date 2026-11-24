# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Labels < Grape::Entity
          expose :allows_scoped_labels, as: :allows_scoped_labels,
            documentation: {
              type: 'Boolean', example: true,
              desc: 'Whether scoped labels are available in the project or group. With scoped labels, ' \
                'a work item can have only one label per key, such as one `priority::` label.'
            }
          expose :labels, using: ::API::Entities::WorkItems::Label,
            documentation: {
              type: 'Entities::WorkItems::Label', is_array: true,
              desc: 'Labels applied to the work item. Empty if it has no labels.'
            }

          private

          def allows_scoped_labels
            resource_parent = options[:resource_parent]
            return object.allows_scoped_labels? unless resource_parent

            resource_parent.licensed_feature_available?(:scoped_labels)
          end
        end
      end
    end
  end
end
