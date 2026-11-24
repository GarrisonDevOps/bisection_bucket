# frozen_string_literal: true

module EE
  module WorkItems
    module DataSync
      module Handlers
        module CopyDataHandler
          extend ::Gitlab::Utils::Override

          override :execute
          def execute
            service_response = super
            new_work_item = service_response[:work_item]

            return service_response unless service_response.success? && maintaining_elasticsearch?(new_work_item)

            trigger_elastic_search_updates(new_work_item) # we need to propagate new permissions to notes

            service_response
          end

          private

          def trigger_elastic_search_updates(new_work_item)
            new_work_item.maintain_elasticsearch_update
            new_work_item.maintain_elasticsearch_issue_notes_update
          end

          def maintaining_elasticsearch?(new_work_item)
            new_work_item.maintaining_elasticsearch? && new_work_item.project&.maintaining_indexed_associations?
          end
        end
      end
    end
  end
end
