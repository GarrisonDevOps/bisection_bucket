# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        class Mention
          TEMPLATE = <<~GOAL.strip
            <gitlab_context>
            %{source_context}
            Requesting user: @%{triggered_by_username}

            The conversation below ends with the message you are answering. Earlier messages provide context.
            Your final response is delivered automatically to this discussion. Include @%{triggered_by_username} in it to notify them. No tool call is needed to deliver your final response.

            Use the final response to answer questions and report investigation findings. A request made in this discussion does not by itself require posting a separate comment through a tool.

            Post a separate comment when the requester explicitly asks for one or when the requested work needs a discussion artifact separate from your answer. If you post a separate comment through a tool, use the final response to briefly confirm or summarize that work rather than repeat the comment.
            If you open a merge request as part of the requested work, assign it to @%{triggered_by_username} unless instructed otherwise.
            </gitlab_context>

            <conversation>
            %{user_input}
            </conversation>
          GOAL

          def self.template
            TEMPLATE
          end

          def self.vars(resource:, params:)
            resource_url = Gitlab::UrlBuilder.build(resource)
            triggered_by_username = params[:triggered_by_username].to_s
            note_id = params[:note_id]
            note_url = note_id ? "#{resource_url}#note_#{note_id}" : resource_url

            default_context = "#{Developer.resource_display_name(resource).capitalize}: #{note_url}"
            source_context = params[:source_context] || default_context

            {
              triggered_by_username: triggered_by_username,
              source_context: source_context
            }
          end
        end
      end
    end
  end
end
