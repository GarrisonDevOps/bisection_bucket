# frozen_string_literal: true

module Import
  module Sync
    module Repositories
      # Downloads one page of the LFS objects that the repository's refs point to and the project does not have
      # yet. Objects already linked to the project are skipped, so the next pass continues with the next page.
      class ReconcileLfsObjectsService
        FAILURE_MESSAGE = 'GitHub LFS update failed'
        MAX_OBJECTS_PER_PASS = 100

        def initialize(project, authentication:, lease_context:, revisions: nil)
          @project = project
          @authentication = authentication
          @lease_context = lease_context
          @revisions = revisions
        end

        # Returns false when the page is full, so more objects may still be missing.
        def execute
          return true if revisions == []

          downloaded_count = 0
          complete = true

          download_list_service.each_list_item do |download_object|
            download!(download_object)
            lease_context.renew!
            downloaded_count += 1

            if downloaded_count >= MAX_OBJECTS_PER_PASS
              complete = false
              break
            end
          end

          complete
        rescue ApplicationLease::LostLeaseError, Errors::MissingCredentialsError,
          ::Import::Github::RefreshOauthTokenService::BadRefreshTokenError
          raise
        rescue StandardError, GRPC::Core::CallError
          raise Errors::LfsReconciliationError, FAILURE_MESSAGE, cause: nil
        end

        private

        attr_reader :project, :authentication, :lease_context, :revisions

        def download_list_service
          ::Projects::LfsPointers::LfsObjectDownloadListService.new(
            project,
            nil,
            import_url: authentication.repository_url,
            http_authorization_header: authentication.http_authorization_header,
            updated_revisions: revisions
          )
        end

        def download!(download_object)
          result = ::Projects::LfsPointers::LfsDownloadService.new(project, download_object).execute
          return if result&.dig(:status) == :success

          raise Errors::LfsReconciliationError, FAILURE_MESSAGE
        end
      end
    end
  end
end
