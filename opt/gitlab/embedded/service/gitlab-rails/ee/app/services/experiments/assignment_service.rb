# frozen_string_literal: true

module Experiments
  class AssignmentService
    include Gitlab::Experiment::Dsl

    def initialize(experiment_name:, current_user:, context_params: {}, variant: nil)
      @experiment_name = experiment_name.to_s
      @variant = variant&.to_sym
      @context_params = context_params.to_h.symbolize_keys
      @current_user = current_user
    end

    def write
      return ServiceResponse.error(message: 'Variant is required') if variant.blank?

      result = resolve_context
      return result if result.error?

      context = result.payload[:context]
      exp = experiment(experiment_name.to_sym, **context)
      exp.cache.write(variant.to_s)

      ServiceResponse.success(payload: {
        experiment: experiment_name,
        variant: variant.to_s,
        context_key: exp.cache_key,
        cached: true
      })
    end

    def read
      result = resolve_context
      return result if result.error?

      context = result.payload[:context]
      exp = experiment(experiment_name.to_sym, **context)
      cached_variant = exp.cache.read

      ServiceResponse.success(payload: {
        experiment: experiment_name,
        variant: cached_variant,
        context_key: exp.cache_key,
        cached: cached_variant.present?
      })
    end

    def clear
      result = resolve_context
      return result if result.error?

      context = result.payload[:context]
      experiment(experiment_name.to_sym, **context).cache.delete

      ServiceResponse.success
    end

    private

    attr_reader :experiment_name, :variant, :context_params, :current_user

    def resolve_context
      ContextResolver.new(
        experiment_name: experiment_name,
        context_params: context_params,
        current_user: current_user
      ).resolve
    end
  end
end
