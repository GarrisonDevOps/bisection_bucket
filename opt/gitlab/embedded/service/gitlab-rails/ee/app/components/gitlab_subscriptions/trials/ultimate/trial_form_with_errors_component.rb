# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module Ultimate
      class TrialFormWithErrorsComponent < TrialFormComponent
        extend ::Gitlab::Utils::Override

        def initialize(**kwargs)
          super

          @namespace_create_errors = kwargs[:namespace_create_errors]
        end

        private

        attr_reader :namespace_create_errors

        override :user_data
        def user_data
          super.merge(
            extract_and_camelize_params([:first_name, :last_name, :company_name, :phone_number, :country, :state])
          )
        end

        override :namespace_data
        def namespace_data
          super.merge(extract_and_camelize_params([:new_group_name])).merge(createErrors: namespace_create_errors)
        end

        def extract_and_camelize_params(keys)
          params.slice(*keys).transform_keys { |key| key.to_s.camelize(:lower).to_sym }
        end
      end
    end
  end
end
