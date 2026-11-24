# frozen_string_literal: true

module EE
  module Banzai
    module ReferenceParser
      module EpicParser
        # rubocop: disable CodeReuse/ActiveRecord
        def records_for_nodes(nodes)
          @epics_for_nodes ||= grouped_objects_for_nodes(
            nodes,
            ::Epic.includes(node_includes),
            self.class.data_attribute
          )
        end
        # rubocop: enable CodeReuse/ActiveRecord

        private

        def node_includes
          includes = [
            :author,
            :group
          ]
          includes << { work_item: [:assignees, :milestone] } if context.options[:extended_preload]

          includes
        end
      end
    end
  end
end
