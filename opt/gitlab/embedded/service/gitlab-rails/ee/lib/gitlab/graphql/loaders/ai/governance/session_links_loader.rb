# frozen_string_literal: true

module Gitlab
  module Graphql
    module Loaders
      module Ai
        module Governance
          # Batch loads the links of AI governance sessions, with one query per kind across a page.
          # Sessions are ClickHouse row hashes, not ActiveRecord models, so this is keyed by
          # `workflow_id` instead of building on `LazyRelationLoader`.
          class SessionLinksLoader
            MODELS = {
              merge_request: ::Ai::DuoWorkflows::WorkflowMergeRequest,
              note: ::Ai::DuoWorkflows::WorkflowNote,
              work_item: ::Ai::DuoWorkflows::WorkflowWorkItem
            }.freeze

            def initialize(kind, workflow_id)
              @kind = kind
              @model = MODELS.fetch(kind)
              @workflow_id = workflow_id
            end

            def find
              # Sessions from external agents have no workflow and no links.
              return [] unless workflow_id

              BatchLoader::GraphQL.for(workflow_id.to_i)
                .batch(key: "ai-governance-session-#{kind}-links", default_value: []) do |ids, loader|
                model.where(workflow_id: ids).group_by(&:workflow_id).each do |id, links| # rubocop:disable CodeReuse/ActiveRecord -- batch lookup on an indexed column
                  loader.call(id, links.sort_by(&:id))
                end
              end
            end

            private

            attr_reader :kind, :model, :workflow_id
          end
        end
      end
    end
  end
end
