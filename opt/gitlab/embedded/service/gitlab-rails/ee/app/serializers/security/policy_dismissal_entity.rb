# frozen_string_literal: true

module Security
  class PolicyDismissalEntity < Grape::Entity
    include RequestAwareEntity

    expose :id
    expose :created_at
    expose :updated_at
    expose :project_id

    expose :project_name do |policy_dismissal|
      policy_dismissal.project&.name
    end

    expose :project_path do |policy_dismissal|
      policy_dismissal.project&.full_path
    end

    expose :merge_request_id
    expose :security_policy_id
    expose :user_id
    expose :security_findings_uuids
    expose :comment

    expose :dismissal_types do |policy_dismissal|
      policy_dismissal.dismissal_types.map do |type|
        Security::PolicyDismissal::DISMISSAL_TYPES.key(type).to_s.humanize
      end
    end

    expose :user_name do |policy_dismissal|
      policy_dismissal.user&.name
    end

    expose :user_path do |policy_dismissal|
      user_path(policy_dismissal.user) if policy_dismissal.user
    end

    expose :merge_request_path, if: ->(policy_dismissal, _) {
      can_read_merge_request?(policy_dismissal)
    } do |policy_dismissal|
      project_merge_request_path(policy_dismissal.project, policy_dismissal.merge_request)
    end

    expose :merge_request_reference, if: ->(policy_dismissal, _) {
      can_read_merge_request?(policy_dismissal)
    } do |policy_dismissal|
      policy_dismissal.merge_request.to_reference
    end

    private

    def can_read_merge_request?(policy_dismissal)
      can?(current_user, :read_merge_request, policy_dismissal.merge_request)
    end

    def current_user
      request.current_user if request.respond_to?(:current_user)
    end
  end
end
