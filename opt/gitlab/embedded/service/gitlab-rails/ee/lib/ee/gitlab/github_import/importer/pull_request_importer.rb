# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Importer
        module PullRequestImporter
          extend ::Gitlab::Utils::Override
          include ProvisioningSyncRepository

          # The mapping is written only after Git data is applied, because the sync treats a
          # mapping with an unchanged updated_at as fully imported.
          override :execute
          def execute
            repository = provisioning_sync_repository
            merge_request = super
            return merge_request unless repository && merge_request && pull_request.provider_id

            ::Import::Sync::ExternalObject.record!(
              repository: repository,
              kind: :pull_request,
              provider_object_xid: pull_request.provider_id,
              local_record: merge_request,
              provider_updated_at: pull_request.updated_at&.in_time_zone
            )

            merge_request
          end
        end
      end
    end
  end
end
