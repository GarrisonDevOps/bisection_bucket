# frozen_string_literal: true

module Integrations
  module GoogleCloudPlatform
    class ArtifactRegistry < Integration
      include HasAvatar

      SECTION_TYPE_GOOGLE_ARTIFACT_MANAGEMENT = 'google_artifact_management'

      attribute :alert_events, default: false
      attribute :commit_events, default: false
      attribute :confidential_issues_events, default: false
      attribute :confidential_note_events, default: false
      attribute :issues_events, default: false
      attribute :job_events, default: false
      attribute :merge_requests_events, default: false
      attribute :note_events, default: false
      attribute :pipeline_events, default: false
      attribute :push_events, default: false
      attribute :tag_push_events, default: false
      attribute :wiki_page_events, default: false
      attribute :comment_on_event_enabled, default: false

      with_options if: :activated? do
        validates :artifact_registry_project_id, presence: true
        validates :artifact_registry_location, presence: true
        validates :artifact_registry_repositories, presence: true
      end

      field :artifact_registry_project_id,
        required: true,
        section: SECTION_TYPE_CONFIGURATION,
        title: -> { s_('GoogleCloud|Google Cloud project ID') },
        label_description: -> { s_('GoogleCloud|Project with the Artifact Registry repository.') },
        description: -> { _('ID of the Google Cloud project.') },
        help: -> { artifact_registry_project_id_help }

      field :artifact_registry_repositories,
        required: true,
        section: SECTION_TYPE_CONFIGURATION,
        title: -> { s_('GoogleCloud|Repository name') },
        help: -> {
          s_('GoogleCloud|Can be up to 63 lowercase letters, numbers, or hyphens. ' \
             'Must start with a letter and end with a letter or number. ' \
             'Repository must be Docker format and Standard mode.')
        },
        description: -> { _('Repository of Artifact Registry.') }

      field :artifact_registry_location,
        required: true,
        section: SECTION_TYPE_CONFIGURATION,
        title: -> { s_('GoogleCloud|Repository location') },
        description: 'Location of the Artifact Registry repository.'

      alias_method :artifact_registry_repository, :artifact_registry_repositories

      def self.title
        s_('GoogleCloud|Google Artifact Management')
      end

      def self.description
        s_('GoogleCloud|Manage your artifacts in Google Artifact Registry.')
      end

      def self.to_param
        'google_cloud_platform_artifact_registry'
      end

      def sections
        [
          {
            type: SECTION_TYPE_GOOGLE_ARTIFACT_MANAGEMENT
          }
        ]
      end

      def self.supported_events
        []
      end

      def self.default_test_event
        'current_user'
      end

      # TODO This will need an update when the integration handles multi repositories
      # artifact_registry_repository will not be available anymore.
      def repository_full_name
        "projects/#{artifact_registry_project_id}/" \
          "locations/#{artifact_registry_location}/" \
          "repositories/#{artifact_registry_repository}"
      end

      def ci_variables
        return [] unless ::Gitlab::Saas.feature_available?(:google_cloud_support) && activated?

        [
          { key: 'GOOGLE_ARTIFACT_REGISTRY_PROJECT_ID', value: artifact_registry_project_id },
          { key: 'GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_NAME', value: artifact_registry_repository },
          { key: 'GOOGLE_ARTIFACT_REGISTRY_REPOSITORY_LOCATION', value: artifact_registry_location }
        ]
      end

      def self.artifact_registry_project_id_help
        url = 'https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects'

        format(
          s_('GoogleCloud|%{link_start}Where’s my project ID? %{icon}%{link_end} ' \
             'Can be 6 to 30 lowercase letters, numbers, or hyphens. ' \
             'Must start with a letter and end with a letter or number. ' \
             'Example: %{code_start}my-sample-project-191923%{code_end}.'),
          link_start: format('<a target="_blank" rel="noopener noreferrer" href="%{url}">', url: url).html_safe, # rubocop:disable Rails/OutputSafety -- It is fine to call html_safe here
          link_end: '</a>'.html_safe,
          code_start: '<code>'.html_safe,
          code_end: '</code>'.html_safe,
          icon: ApplicationController.helpers.sprite_icon('external-link', aria_label: _('(external link)')).html_safe # rubocop:disable Rails/OutputSafety -- It is fine to call html_safe here
        )
      end

      override :testable?
      def testable?
        # Integration must be persisted and active to execute during the test.
        # https://gitlab.com/gitlab-org/gitlab/-/blob/ffab9d0cd946e725e9b7878e9c46991dbc1d478a/ee/app/services/google_cloud/artifact_registry/base_project_service.rb#L42
        super && persisted? && active?
      end

      def test(data)
        response = ::GoogleCloud::ArtifactRegistry::GetRepositoryService # rubocop:disable CodeReuse/ServiceClass -- the implementation is tied to existing strategy of testing an integration
          .new(project: project, current_user: data[:current_user]).execute

        { success: response.success?, result: response.message }
      end
    end
  end
end
