# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      class GitlabContext
        include Concerns::XrayContext
        include Gitlab::Utils::StrongMemoize

        attr_accessor :current_user, :container, :resource, :ai_request, :tools_used, :extra_resource, :request_id,
          :started_at,
          :current_file, :agent_version, :additional_context

        attr_reader :project, :is_duo_code_review

        delegate :current_page_params, to: :authorized_resource, allow_nil: true

        # rubocop:disable Metrics/ParameterLists -- we probably need to rethink this initializer
        def initialize(
          current_user:, container:, resource:, ai_request:, extra_resource: {}, request_id: nil,
          started_at: nil,
          current_file: {}, agent_version: nil, additional_context: [], is_duo_code_review: false
        )
          @current_user = current_user
          @container = container
          @resource = resource
          @project = resource.is_a?(Project) ? resource : resource.try(:project)
          @ai_request = ai_request
          @tools_used = []
          @extra_resource = extra_resource
          @request_id = request_id
          @started_at = started_at
          @current_file = (current_file || {}).with_indifferent_access
          @agent_version = agent_version
          @additional_context = additional_context
          @is_duo_code_review = is_duo_code_review
        end
        # rubocop:enable Metrics/ParameterLists

        def resource_serialized(content_limit:)
          return '' unless authorized_resource

          serialization_options = { content_limit: content_limit }

          # Only pass is_duo_code_review for MergeRequest resources
          if authorized_resource.is_a?(::Ai::AiResource::MergeRequest)
            serialization_options[:is_duo_code_review] = is_duo_code_review
          end

          authorized_resource.serialize_for_ai(**serialization_options)
                             .to_xml(root: :root, skip_types: true, skip_instruct: true)
        end

        def language
          ::CodeSuggestions::ProgrammingLanguage.detect_from_filename(current_file[:file_name].to_s)
        end
        strong_memoize_attr :language

        private

        # @return [Ai::AiResource::BaseAiResource]
        def authorized_resource
          ::Ai::AiResource::Wrapper.new(current_user, resource).wrap
        end
      end
    end
  end
end
