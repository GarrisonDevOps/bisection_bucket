# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class LinkedItems < Grape::Entity
          # Reads from the issues.blocking_issues_count counter cache column, which the default
          # ActiveRecord select includes. Any narrowed .select(...) on the listing relation that
          # omits this column would silently return 0 instead of issuing N queries.
          expose :blocking_count, documentation: {
            type: 'Integer', example: 2, desc: 'Number of work items this work item blocks.'
          } do |feature|
            feature.work_item.blocking_issues_count
          end

          expose :blocked_by_count, documentation: {
            type: 'Integer', example: 1, desc: 'Number of work items that block this work item.'
          } do |feature, options|
            options[:blocked_by_counts]&.fetch(feature.work_item.id, 0) || 0
          end
        end
      end
    end
  end
end
