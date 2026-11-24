# frozen_string_literal: true

module EE
  module MergeRequestPollWidgetEntity
    include ::API::Helpers::RelatedResourcesHelpers
    extend ActiveSupport::Concern

    prepended do
      expose :merge_pipelines_enabled?, as: :merge_pipelines_enabled do |merge_request|
        merge_request.target_project.merge_pipelines_enabled?
      end

      expose :can_retry_external_status_checks do |merge_request|
        can?(current_user, :retry_failed_status_checks, merge_request)
      end

      expose :merge_trains_skip_train_allowed?, as: :merge_trains_skip_train_allowed do |merge_request|
        merge_request.target_project.merge_trains_skip_train_allowed?
      end

      expose :merge_train_enforced do |merge_request|
        merge_request.target_project.merge_train_enforced_for?(current_user)
      end

      expose :can_resolve_with_ai do |merge_request|
        merge_request.can_resolve_with_ai?(current_user)
      end
    end
  end
end
