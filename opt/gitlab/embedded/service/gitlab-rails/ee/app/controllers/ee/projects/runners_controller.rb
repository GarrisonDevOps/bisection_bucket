# frozen_string_literal: true

module EE
  module Projects
    module RunnersController
      extend ActiveSupport::Concern

      prepended do
        before_action(only: [:new, :show, :edit]) do
          push_licensed_feature(:runner_maintenance_note_for_namespace, project)
        end
      end
    end
  end
end
