# frozen_string_literal: true

module Ci
  class CreateProjectSubscriptionService < BaseService
    def initialize(project:, upstream_project:, user:)
      super(project, user)
      @upstream_project = upstream_project
    end

    def execute
      error = validate
      return error if error.present?

      subscription = project.upstream_project_subscriptions.create(
        upstream_project: upstream_project,
        author: current_user
      )

      if subscription.errors.present?
        return ServiceResponse.error(
          message: subscription.errors.full_messages
        )
      end

      ServiceResponse.success(payload: { subscription: subscription })
    end

    private

    attr_reader :upstream_project

    def validate
      return if allowed?

      ServiceResponse.error(message: "Feature unavailable for this user.")
    end

    def allowed?
      project.licensed_feature_available?(:ci_project_subscriptions) &&
        can?(current_user, :subscribe_to_upstream_pipeline, upstream_project) &&
        can?(current_user, :create_pipeline_subscription, project)
    end
  end
end
