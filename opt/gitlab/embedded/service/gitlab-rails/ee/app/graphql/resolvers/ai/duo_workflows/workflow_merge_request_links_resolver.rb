# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowMergeRequestLinksResolver < WorkflowLinksBaseResolver
        type Types::Ai::DuoWorkflows::WorkflowMergeRequestLinkType.connection_type, null: true

        self.link_type_enum = Types::Ai::DuoWorkflows::MergeRequestLinkTypeEnum
        self.links_association = :merge_request_links

        private

        def preloads
          { [:merge_request, :reviewers] => [{ merge_request: :reviewers }] }
        end
      end
    end
  end
end
