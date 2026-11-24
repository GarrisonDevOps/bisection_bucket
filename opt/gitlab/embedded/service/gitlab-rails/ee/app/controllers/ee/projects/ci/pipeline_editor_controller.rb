# frozen_string_literal: true

module EE
  module Projects
    module Ci
      module PipelineEditorController
        extend ActiveSupport::Concern

        prepended do
          before_action only: [:show] do
            push_frontend_ability(
              ability: :access_duo_agentic_chat,
              resource: @project,
              user: current_user
            )
          end
        end
      end
    end
  end
end
