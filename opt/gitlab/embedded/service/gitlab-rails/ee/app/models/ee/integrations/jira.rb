# frozen_string_literal: true

module EE
  module Integrations
    module Jira
      extend ActiveSupport::Concern
      include ::Gitlab::Utils::StrongMemoize

      MAX_URL_LENGTH = 4000

      SECTION_TYPE_JIRA_VERIFICATION = 'jira_verification'

      API_ENDPOINTS = {
        create_issue: "/rest/api/2/issue",
        find_project: "/rest/api/2/project/%s"
      }.freeze

      prepended do
        validates :project_key, presence: true, if: :project_key_required?
        validates :vulnerabilities_issuetype, presence: true, if: :vulnerabilities_enabled
        validates :project_keys,
          length: {
            maximum: 100,
            message: N_('is too long (maximum is 100 entries)')
          }

        field :vulnerabilities_enabled,
          required: false,
          type: :checkbox,
          api_only: true,
          description: -> { s_('JiraIntegration|Turn on Jira issue creation for GitLab vulnerabilities.') }

        field :vulnerabilities_issuetype,
          required: false,
          type: :select,
          api_only: true,
          description: -> { s_('JiraIntegration|Jira issue type to use when creating issues from vulnerabilities.') }

        field :project_key,
          required: false,
          type: :text,
          api_only: true,
          description: -> {
            s_('JiraIntegration|Key of the project to use when creating issues from vulnerabilities.' \
              'This parameter is required if using the integration to create Jira issues from vulnerabilities.')
          }

        field :customize_jira_issue_enabled,
          required: false,
          type: :checkbox,
          api_only: true,
          description: -> {
            s_('JiraIntegration|When set to `true`, opens a prefilled form on the Jira instance' \
              'when creating a Jira issue from a vulnerability.')
          }

        field :jira_check_enabled,
          section: SECTION_TYPE_JIRA_VERIFICATION,
          type: :checkbox,
          title: -> { s_('JiraService|Enable Jira verification') },
          description: -> {
            s_('JiraIntegration|Verify Jira issues referenced in commit messages exist before allowing the push.')
          }

        field :jira_exists_check_enabled,
          section: SECTION_TYPE_JIRA_VERIFICATION,
          type: :checkbox,
          title: -> { s_('JiraService|Check issue exists') },
          description: -> { s_('JiraIntegration|Verify the Jira issues referenced in commit messages exist in Jira.') }

        field :jira_assignee_check_enabled,
          section: SECTION_TYPE_JIRA_VERIFICATION,
          type: :checkbox,
          title: -> { s_('JiraService|Check assignee') },
          description: -> {
            s_('JiraIntegration|Verify the committer is the assignee of the Jira issues referenced in commit messages.')
          }

        field :jira_status_check_enabled,
          section: SECTION_TYPE_JIRA_VERIFICATION,
          type: :checkbox,
          title: -> { s_('JiraService|Check issue status') },
          description: -> { s_('JiraIntegration|Verify the status of Jira issues referenced in commit messages.') }

        field :jira_allowed_statuses_as_string,
          section: SECTION_TYPE_JIRA_VERIFICATION,
          type: :text,
          title: -> { s_('JiraService|Allowed statuses') },
          description: -> { s_('JiraIntegration|Comma-separated list of allowed Jira issue statuses.') },
          placeholder: 'Ready, In Progress, Review'

        data_field :jira_check_enabled
        data_field :jira_exists_check_enabled
        data_field :jira_assignee_check_enabled
        data_field :jira_status_check_enabled
        data_field :jira_allowed_statuses_string
        data_field :jira_allowed_statuses_as_string
      end

      class_methods do
        def instance_level(organization)
          for_organization(organization).first
        end
      end

      def sections
        sections = super

        # Add Jira verification section for non-instance level integrations
        unless instance_level?
          # Find the index where to insert the verification section
          # Insert it before the Jira issues section
          jira_issues_index = sections.find_index { |section| section[:type] == 'jira_issues' } || sections.length

          verification_section = {
            type: SECTION_TYPE_JIRA_VERIFICATION,
            title: s_('JiraService|Jira verification'),
            description: s_('JiraService|Verify Jira issues referenced in commit messages against ' \
              'specific rules before allowing the push.'),
            plan: 'premium'
          }

          sections.insert(jira_issues_index, verification_section)
        end

        sections
      end

      def jira_vulnerabilities_integration_available?
        if parent.present?
          parent.licensed_feature_available?(:jira_vulnerabilities_integration)
        else
          License.feature_available?(:jira_vulnerabilities_integration)
        end
      end

      def jira_vulnerabilities_integration_enabled?
        jira_vulnerabilities_integration_available? && vulnerabilities_enabled
      end

      def configured_to_create_issues_from_vulnerabilities?
        active? && project_key.present? &&
          vulnerabilities_issuetype.present? && jira_vulnerabilities_integration_enabled?
      end
      strong_memoize_attr :configured_to_create_issues_from_vulnerabilities?

      def test(_)
        super.then do |result|
          next result unless result[:success]
          next result unless jira_vulnerabilities_integration_enabled?

          result.merge(data: { issuetypes: issue_types })
        end
      end

      def new_issue_url_with_predefined_fields(summary, description)
        escaped_summary = CGI.escape(summary)
        escaped_description = CGI.escape(description)

        # Put summary and description at the end of the URL in case we need to trim it
        web_url('secure/CreateIssueDetails!init.jspa', pid: jira_project_id, issuetype: vulnerabilities_issuetype)
          .concat("&summary=#{escaped_summary}&description=#{escaped_description}")
          .slice(0..MAX_URL_LENGTH)
      end

      def create_issue(summary, description, current_user)
        return if client_url.blank?

        path = API_ENDPOINTS[:create_issue]

        jira_request(path) do
          issue = client.Issue.build
          issue.save(
            fields: {
              project: { id: jira_project_id },
              issuetype: { id: vulnerabilities_issuetype },
              summary: summary,
              description: description
            }
          )
          log_usage(:create_issue, current_user)
          issue
        end
      end

      private

      def project_key_required?
        vulnerabilities_enabled
      end
      strong_memoize_attr :project_key_required?

      # Returns internal JIRA Project ID
      #
      # @return [String, nil] the internal JIRA ID of the Project
      def jira_project_id
        jira_project&.id
      end

      # Returns JIRA Project for selected Project Key
      #
      # @return [JIRA::Resource::Project, nil] the object that represents JIRA Projects
      def jira_project
        return unless client_url.present?

        jira_request(API_ENDPOINTS[:find_project] % project_key) { client.Project.find(project_key) }
      end
      strong_memoize_attr :jira_project

      # Returns list of available Issue types in selected JIRA Project
      #
      # @return [Array] the array of objects with JIRA Issuetype ID, Name and Description
      def issue_types
        issuetypes = jira_project.blank? ? client.Issuetype.all : jira_project.issuetypes

        issuetypes.reject(&:subtask).map do |issue_type|
          {
            id: issue_type.id,
            name: issue_type.name,
            description: issue_type.description
          }
        end
      end
    end
  end
end
