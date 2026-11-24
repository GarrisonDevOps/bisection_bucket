# frozen_string_literal: true

module DeclarativePolicy
  # Used when the name of a delegate is mentioned in
  # the rule DSL.
  class DelegateDsl
    def initialize(rule_dsl, delegate_name)
      @rule_dsl = rule_dsl
      @delegate_name = delegate_name
    end

    def method_missing(msg, *args)
      return super unless args.empty? && !block_given?

      @rule_dsl.delegate(@delegate_name, msg)
    end

    def respond_to_missing?(_msg, _include_all)
      true
    end
  end
end
