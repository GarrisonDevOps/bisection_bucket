# frozen_string_literal: true

module Ai
  module ModelSelection
    module Concerns
      module GitlabDefaultModelParams
        extend ActiveSupport::Concern
        MODEL_PROVIDER = 'gitlab'
        IDENTIFIER_FOR_DEFAULT_MODEL = ''

        private

        def params_as_if_gitlab_default_model(feature_name)
          return code_completion_default_params if feature_name.to_s == 'code_completions'

          {
            provider: MODEL_PROVIDER,
            identifier: IDENTIFIER_FOR_DEFAULT_MODEL,
            feature_setting: feature_name.to_s
          }
        end

        def code_completion_default_params
          {
            model_name: IDENTIFIER_FOR_DEFAULT_MODEL,
            model_provider: MODEL_PROVIDER
          }
        end
      end
    end
  end
end
