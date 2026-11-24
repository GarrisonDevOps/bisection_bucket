# frozen_string_literal: true

module Integrations
  module GoogleCloudPlatform
    class WorkloadIdentityFederation < Integration
      include HasAvatar

      SECTION_TYPE_GOOGLE_CLOUD_IAM = 'google_cloud_iam'

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

      validates :workload_identity_federation_project_id, format: /\A[a-z0-9-]{6,30}\z/, allow_blank: true
      validates :workload_identity_pool_id, format: /\A[a-z0-9-]{4,32}\z/, allow_blank: true
      validates :workload_identity_pool_provider_id, format: /\A[a-z0-9-]{4,32}\z/, allow_blank: true

      with_options if: :activated? do
        validates :workload_identity_federation_project_id, presence: true
        validates :workload_identity_federation_project_number, presence: true, numericality: { only_integer: true }
        validates :workload_identity_pool_id, presence: true
        validates :workload_identity_pool_provider_id, presence: true
      end

      field :workload_identity_federation_project_id,
        required: true,
        section: SECTION_TYPE_CONFIGURATION,
        title: -> { s_('GoogleCloud|Project ID') },
        description: -> {
          s_('GoogleCloud|Google Cloud project ID for the Workload Identity Federation.')
        },
        help: -> {
          format(
            s_('GoogleCloud|Can be 6 to 30 lowercase letters, numbers, or hyphens. ' \
              'Must start with a letter and end with a letter or number. ' \
              'Example: %{code_open}my-sample-project-191923%{code_close}'),
            {
              code_open: '<code>',
              code_close: '</code>'
            }
          )
        }

      field :workload_identity_federation_project_number,
        required: true,
        section: SECTION_TYPE_CONFIGURATION,
        title: -> { s_('GoogleCloud|Project number') },
        description: -> {
          s_('GoogleCloud|Google Cloud project number for the Workload Identity Federation.')
        },
        help: -> {
          format(
            s_('GoogleCloud|Example: %{code_open}314053285323%{code_close}'),
            {
              code_open: '<code>',
              code_close: '</code>'
            }
          )
        }

      field :workload_identity_pool_id,
        required: true,
        section: SECTION_TYPE_CONFIGURATION,
        title: -> { s_('GoogleCloud|Pool ID') },
        description: -> {
          s_('GoogleCloud|ID of the Workload Identity Pool.')
        },
        help: -> {
          format(
            s_('GoogleCloud|Can be 4 to 32 lowercase letters, numbers, or hyphens.')
          )
        }

      field :workload_identity_pool_provider_id,
        required: true,
        section: SECTION_TYPE_CONFIGURATION,
        title: -> { s_('GoogleCloud|Provider ID') },
        description: -> {
          s_('GoogleCloud|ID of the Workload Identity Pool provider.')
        },
        help: -> {
          format(
            s_('GoogleCloud|Can be 4 to 32 lowercase letters, numbers, or hyphens.')
          )
        }

      def self.title
        s_('GoogleCloud|Google Cloud IAM')
      end

      def self.description
        s_('GoogleCloud|Manage permissions for Google Cloud resources with Identity and Access Management (IAM).')
      end

      def self.to_param
        'google_cloud_platform_workload_identity_federation'
      end

      def sections
        [
          {
            type: SECTION_TYPE_GOOGLE_CLOUD_IAM
          }
        ]
      end

      def self.supported_events
        []
      end

      def self.wlif_issuer_url(group_or_project)
        "#{::GoogleCloud.glgo_base_url}/oidc/#{group_or_project.root_ancestor.path}"
      end

      # used when setting up WLIF pools
      # google cloud supports a max of 50 attributes
      # https://cloud.google.com/iam/docs/workload-identity-federation#mapping
      #
      # list of all possible attributes at
      # https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html#token-payload
      def self.jwt_claim_mapping
        access_attributes = Gitlab::Access.sym_options_with_owner.keys
        attribute_mapping = access_attributes.to_h do |k, _v|
          ["attribute.#{k}_access", "assertion.#{k}_access"]
        end

        additional_attributes = %w[
          namespace_id
          namespace_path
          project_id
          project_path
          user_id
          user_login
          user_email
          user_access_level
        ]
        additional_attributes.each { |a| attribute_mapping["attribute.#{a}"] = "assertion.#{a}" }

        attribute_mapping['google.subject'] = 'assertion.sub'
        attribute_mapping
      end

      def self.jwt_claim_mapping_script_value
        jwt_claim_mapping.map { |k, v| "#{k}=#{v}" }.join(',')
      end

      # We will make the integration testable in https://gitlab.com/gitlab-org/gitlab/-/issues/439885
      def testable?
        false
      end

      def identity_provider_resource_name
        return unless ::Gitlab::Saas.feature_available?(:google_cloud_support) && activated?

        "//#{identity_pool_resource_name}/providers/#{workload_identity_pool_provider_id}"
      end

      def identity_pool_resource_name
        return unless ::Gitlab::Saas.feature_available?(:google_cloud_support) && activated?

        "iam.googleapis.com/projects/#{workload_identity_federation_project_number}/" \
          "locations/global/workloadIdentityPools/#{workload_identity_pool_id}"
      end
    end
  end
end
