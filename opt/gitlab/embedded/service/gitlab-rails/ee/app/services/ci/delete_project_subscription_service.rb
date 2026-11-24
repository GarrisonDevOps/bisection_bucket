# frozen_string_literal: true

module Ci
  class DeleteProjectSubscriptionService < BaseService
    attr_accessor :subscription

    def initialize(subscription:, user:)
      @subscription = subscription
      @current_user = user
    end

    def execute
      validation_error = validate
      return validation_error if validation_error

      result = subscription.destroy

      if result.errors.present?
        return ServiceResponse.error(
          message: result.errors.full_messages
        )
      end

      ServiceResponse.success(payload: result.downstream_project)
    end

    private

    def validate
      unless subscription.present?
        return ServiceResponse.error(message: "Failed to delete subscription.",
          reason: "Subscription does not exist.")
      end

      return if allowed?

      ServiceResponse.error(message: "Failed to delete subscription.",
        reason: "Feature unavailable for this project.")
    end

    def allowed?
      subscription.downstream_project.licensed_feature_available?(:ci_project_subscriptions) &&
        can?(current_user, :delete_project_subscription, subscription)
    end
  end
end
