# frozen_string_literal: true

module GitlabSubscriptions
  class NamespaceAddOnPurchasesFinder
    def initialize(namespace, add_on:, trial: false, only_active: true)
      @namespace = namespace
      @trial = trial
      @only_active = only_active
      @add_on = add_on
    end

    def execute
      # There will only be one, but we want to return a collection here and then consume it outside of this
      items = GitlabSubscriptions::AddOnPurchase.by_namespace(namespace)
      items = by_add_on(items)
      items = by_active(items)
      by_trial(items)
    end

    private

    attr_reader :namespace, :trial, :only_active, :add_on

    def by_add_on(items)
      case add_on
      when :duo
        items.for_duo_pro_or_duo_enterprise
      when :duo_pro
        items.for_gitlab_duo_pro
      when :duo_enterprise
        items.for_duo_enterprise
      when :duo_core
        items.for_duo_core
      else
        raise ArgumentError, "Unknown add_on: #{add_on}"
      end
    end

    def by_trial(items)
      return items unless trial

      items.trial
    end

    def by_active(items)
      return items unless only_active

      items.active
    end
  end
end
