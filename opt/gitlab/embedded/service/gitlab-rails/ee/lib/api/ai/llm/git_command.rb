# frozen_string_literal: true

module API
  module Ai
    module Llm
      class GitCommand < ::API::Base
        feature_category :code_review_workflow
        urgency :low

        before do
          authenticate!
          check_rate_limit!(:ai_action, scope: { user: current_user })
        end

        namespace 'ai/llm' do
          desc 'Generate Git commands from natural text' do
            detail 'Generates Git commands from natural language input'
            tags ['gitlab_duo']
          end
          params do
            requires :prompt, type: String, desc: 'Prompt used to generate the Git commands.'
          end

          route_setting :authorization, permissions: :create_git_command, boundary_type: :user
          post 'git_command' do
            response = ::Llm::GitCommandService.new(current_user, current_user, declared_params).execute

            if response.success?
              response.payload
            else
              bad_request!(response.message)
            end
          end
        end
      end
    end
  end
end
