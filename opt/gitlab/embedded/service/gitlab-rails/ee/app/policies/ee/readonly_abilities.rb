# frozen_string_literal: true

module EE
  module ReadonlyAbilities
    extend ActiveSupport::Concern

    READONLY_ABILITIES = %i[
      admin_build
      admin_cluster
      admin_container_image
      admin_environment
      admin_feature_flag
      admin_feature_flags_client
      admin_iteration
      admin_merge_request
      admin_pipeline
      admin_pipeline_schedule
      admin_software_license_policy
      admin_trigger
      admin_vulnerability
      admin_wiki
      create_commit_status
      create_container_repository_protection_rule
      create_merge_request_from
      create_merge_request_in
      create_package
      create_release
      create_repository_tag
      create_test_case
      create_vulnerability_feedback
      delete_container_repository_protection_rule
      delete_pipeline_schedule
      delete_repository_tag
      delete_snippet
      push_to_delete_protected_branch
      update_approvers
      update_container_repository_protection_rule
      update_release
      update_repository_tag
      update_vulnerability_feedback
    ].freeze

    READONLY_FEATURES = %i[
      merge_request
      snippet
      wiki
      pipeline
      pipeline_schedule
      build
      trigger
      environment
      deployment
      container_image
      cluster
      vulnerability
      feature_flag
      feature_flags_client
      iteration
    ].freeze

    class_methods do
      def readonly_abilities
        READONLY_ABILITIES
      end

      def readonly_features
        READONLY_FEATURES
      end
    end
  end
end
