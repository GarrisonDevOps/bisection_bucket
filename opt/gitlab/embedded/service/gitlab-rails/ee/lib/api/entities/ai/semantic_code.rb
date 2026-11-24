# frozen_string_literal: true

module API
  module Entities
    module Ai
      module SemanticCode
        class SnippetRange < Grape::Entity
          expose(:start_line, documentation: { type: 'Integer', example: 42 }) \
            { |r, _| r[:start_line] }
          expose(:end_line, documentation: { type: 'Integer', example: 44 }) \
            { |r, _| r[:end_line] }
          expose(:content, documentation: { type: 'String', example: "def authenticate\n  ...\nend" }) \
            { |r, _| r[:content] }
          expose(:score, documentation: { type: 'Float', example: 0.85 }) \
            { |r, _| r[:score] }
        end

        class GroupedResult < Grape::Entity
          expose(:path, documentation: { type: 'String', example: 'app/models/user.rb' }) \
            { |g, _| g[:path] }
          expose(:blob_id, documentation: { type: 'String', example: 'abc123def456' }) \
            { |g, _| g[:blob_id] }
          expose(:file_url,
            documentation: { type: 'String', example: 'https://gitlab.com/group/project/-/blob/main/user.rb' }) \
            { |g, _| g[:file_url] }
          expose(:score, documentation: { type: 'Float', example: 0.92 }) \
            { |g, _| g[:score] }
          expose(:snippet_ranges,
            documentation: { type: 'Array', is_array: true },
            using: ::API::Entities::Ai::SemanticCode::SnippetRange) \
            { |g, _| g[:snippet_ranges] }
        end

        class Response < Grape::Entity
          expose(:confidence, documentation: {
            type: 'String',
            example: 'high',
            description: 'Overall confidence level based on score distribution: high, medium, low, or unknown'
          }) \
            { |r, _| r[:confidence] }
          expose(:results,
            documentation: { type: 'Array', is_array: true },
            using: ::API::Entities::Ai::SemanticCode::GroupedResult) \
            { |r, _| r[:results] }
        end
      end
    end
  end
end
