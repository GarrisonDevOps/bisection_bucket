# frozen_string_literal: true

module DeclarativePolicy
  class Configuration
    ConfigurationError = Class.new(StandardError)

    def initialize
      @named_policies = {}
      @name_transformation = ->(name) { "#{name}Policy" }
      @class_for = ->(name) { Object.const_get(name) }
    end

    def named_policy(name, policy = nil)
      @named_policies[name] = policy if policy

      @named_policies[name] || raise(ConfigurationError, "No #{name} policy configured")
    end

    def nil_policy(policy = nil)
      @nil_policy = policy if policy

      @nil_policy || ::DeclarativePolicy::NilPolicy
    end

    def name_transformation(&block)
      @name_transformation = block
      nil
    end

    def class_for(&block)
      @class_for = block
      nil
    end

    def policy_class(domain_class_name)
      return unless domain_class_name

      @class_for.call(@name_transformation.call(domain_class_name))
    rescue NameError
      nil
    end
  end
end
