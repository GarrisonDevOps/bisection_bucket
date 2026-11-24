# frozen_string_literal: true

module Gitlab
  module Insights
    module Validators
      class ParamsValidator
        ParamsValidatorError = Class.new(StandardError)
        InvalidTypeError = Class.new(ParamsValidatorError)
        InvalidProjectsError = Class.new(ParamsValidatorError)
        InvalidQueryError = Class.new(ParamsValidatorError)

        SUPPORTER_TYPES = %w[bar line stacked-bar pie].freeze
        MAX_PROJECTS_ONLY = 100

        # @param params [Hash, ActionController::Parameters] the chart's `type`, `query`, and `projects`
        # @param insights_entity [Project, Group] the project or group the chart belongs to
        def initialize(params, insights_entity:)
          @params = params
          @insights_entity = insights_entity
        end

        def validate!
          unless SUPPORTER_TYPES.include?(params[:type])
            raise InvalidTypeError, "Invalid `:type`: `#{params[:type]}`. Allowed values are #{SUPPORTER_TYPES}!"
          end

          if params[:projects]
            unless params[:projects].is_a?(Hash) || params[:projects].is_a?(ActionController::Parameters)
              raise InvalidProjectsError, "Invalid `:projects`: `#{params[:projects]}`. It should be a hash."
            end

            unless params.dig(:projects, :only).is_a?(Array)
              raise InvalidProjectsError, "Invalid `:projects`.`only`: `#{params.dig(:projects, :only)}`. It should be an array."
            end

            if params.dig(:projects, :only).size > MAX_PROJECTS_ONLY && Gitlab::Insights.query_limits_enabled?(insights_entity)
              raise InvalidProjectsError, "Invalid `:projects`.`only`: it can contain at most #{MAX_PROJECTS_ONLY} entries."
            end
          end
        end

        private

        attr_reader :params, :insights_entity
      end
    end
  end
end
