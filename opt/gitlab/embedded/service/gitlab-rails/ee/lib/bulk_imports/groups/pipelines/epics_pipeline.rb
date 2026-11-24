# frozen_string_literal: true

module BulkImports
  module Groups
    module Pipelines
      class EpicsPipeline
        include NdjsonPipeline
        include ::BulkImports::EpicObjectCreator

        relation_name 'epics'

        extractor ::BulkImports::Common::Extractors::NdjsonExtractor, relation: relation

        def load(_context, data)
          epic, original_users_map = data

          return unless epic

          # BulkImports::EpicObjectCreator#create_epic creates a new Epic object instead of saving the one
          # built by RelationFactory and referenced in the original_users_map. This line updates the
          # original_users_map with the newly created Epic object.
          original_users_map[epic] = original_users_map.entries.find do |entry|
            entry.first.is_a?(Epic) && entry.first.iid == epic.iid
          end.last

          copy_epic_user_references_to_work_items(original_users_map)

          push_placeholder_references(original_users_map)

          epic
        end
      end
    end
  end
end
