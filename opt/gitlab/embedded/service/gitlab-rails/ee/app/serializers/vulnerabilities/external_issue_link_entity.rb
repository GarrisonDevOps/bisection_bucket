# frozen_string_literal: true

module Vulnerabilities
  class ExternalIssueLinkEntity < Grape::Entity
    include ::Gitlab::Utils::StrongMemoize
    include RequestAwareEntity

    expose :external_issue_details
    expose :author, using: UserEntity
    expose :created_at
    expose :updated_at
    alias_method :external_issue_link, :object

    private

    def external_issue_details
      return {} unless can_read_issue?
      return {} unless external_issue_link.external_type == 'jira'

      issue = project.jira_integration.find_issue(external_issue_link.external_issue_key)
      Integrations::JiraSerializers::IssueEntity.new(issue, project: project)
    end

    def can_read_issue?
      can?(current_user, :read_issue, project)
    end

    def current_user
      request.current_user if request.respond_to?(:current_user)
    end

    def project
      external_issue_link.vulnerability.project
    end
    strong_memoize_attr :project
  end
end
