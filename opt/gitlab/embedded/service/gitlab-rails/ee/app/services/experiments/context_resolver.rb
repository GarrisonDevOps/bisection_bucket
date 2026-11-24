# frozen_string_literal: true

module Experiments
  # Validates an experiment and resolves its declared `context_keys` from raw
  # request params into the domain objects (User, Namespace, Project) that GLEX
  # needs to compute a cache key.
  #
  # `#resolve` returns a `ServiceResponse`: success carries the resolved context
  # Hash in `payload[:context]`; error carries a message explaining which
  # validation or lookup failed. Callers bail only on error, otherwise continue.
  class ContextResolver
    include Gitlab::Experiment::Dsl

    delegate :context_keys, to: :experiment_class

    def initialize(experiment_name:, current_user:, context_params: {})
      @experiment_name = experiment_name.to_s
      @context_params = context_params.to_h.symbolize_keys
      @current_user = current_user
    end

    def resolve
      error = experiment_definition_error
      return error if error

      apply_default_context

      context = {}
      context_keys.each do |key|
        error = resolve_context_key(key, context)
        return error if error
      end

      ServiceResponse.success(payload: { context: context })
    end

    private

    attr_reader :experiment_name, :context_params, :current_user

    def experiment_definition_error
      definition = Feature::Definition.get(experiment_name.to_sym)
      return ServiceResponse.error(message: "Experiment '#{experiment_name}' not found") unless definition

      unless definition.type.to_s == 'experiment'
        return ServiceResponse.error(message: "'#{experiment_name}' is not an experiment")
      end

      return unless context_keys.blank?

      context_keys_error
    rescue Gitlab::AbstractMethodError
      context_keys_error
    rescue Gitlab::Experiment::UnregisteredExperiment
      ServiceResponse.error(message: "Experiment '#{experiment_name}' is not registered as an experiment class")
    end

    def context_keys_error
      ServiceResponse.error(
        message: "Experiment '#{experiment_name}' does not declare `context_keys` in its experiment class. " \
          "Add `context_keys` to enable assignment reading.")
    end

    def experiment_class
      @experiment_class ||= ApplicationExperiment.constantize(experiment_name)
    end

    # Maps each supported context key to the param it reads and the finder method
    # that resolves it. The `actor` key resolves to a User (so the cache key
    # matches normal GLEX assignment by GlobalID) and reuses the `user` param.
    RESOLVERS = {
      user: { param: :user, finder: :find_user },
      namespace: { param: :namespace, finder: :find_namespace },
      project: { param: :project, finder: :find_project },
      actor: { param: :user, finder: :find_user }
    }.freeze
    private_constant :RESOLVERS

    def resolve_context_key(key, context)
      config = RESOLVERS[key]
      return ServiceResponse.error(message: "Unsupported context key: #{key}") unless config

      param = config[:param]
      value = context_params[param]
      return ServiceResponse.error(message: "#{param} is required") if value.blank?

      resolved = send(config[:finder], value) # rubocop:disable GitlabSecurity/PublicSend -- finder names come from the frozen RESOLVERS hash, not user input
      return ServiceResponse.error(message: "#{param.to_s.camelize} not found: #{value}") unless resolved

      context[key] = resolved
      nil
    end

    def find_user(username)
      return current_user if current_user.username == username

      User.find_by_username(username)
    end

    def find_namespace(full_path)
      Namespace.find_by_full_path(full_path)
    end

    def find_project(full_path)
      Project.find_by_full_path(full_path)
    end

    def apply_default_context
      return unless context_params.empty?

      return if (context_keys & %i[user actor]).empty?

      context_params[:user] = current_user.username
    end
  end
end
