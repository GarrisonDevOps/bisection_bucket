# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module ServerConfig
      class OauthApplicationEnsurer
        # @param [Hash] context
        # @return [Hash]
        def self.ensure(context)
          # NOTE 1: The logic in this class is based on the existing logic in the WebIde::DefaultOauthApplication class.
          # See that class and https://gitlab.com/gitlab-org/gitlab/-/merge_requests/132496 for more context.
          # The main addition here is the automatic update if the attributes have been modified to be incorrect.
          #
          # NOTE 2: Even if there happens to be any unexpected errors due to a race condition due to
          # multiple KAS clients calling this code path concurrently, and any of them get an exception,
          # this is still fine, because the KAS clients have backoff-retry logic, and will successfully retrieve the
          # (now-created) record on the re-attempt.

          context => {
            oauth_application_attributes: Hash => oauth_application_attributes,
            request: (Grape::Request | ActionController::TestRequest) => request,
          }

          # If there is no existing link to the app in application_settings, create the app and link it.
          unless oauth_application
            should_expire_cache = false

            application_settings.transaction do
              # note: This should run very rarely and should be safe for us to do a lock
              #       https://gitlab.com/gitlab-org/gitlab/-/merge_requests/132496#note_1587293087
              application_settings.lock!

              # note: `lock!`` breaks application_settings cache and will trigger another query.
              # We need to double check here by re-attempting to fetch the app from the settings,
              # so that requests previously waiting on the lock can now just skip.
              next if oauth_application

              service = ::Applications::CreateService.new(nil, request, oauth_application_attributes)
              created_oauth_app = service.execute

              # We have to manually check whether it got saved, because ::Applications::CreateService doesn't return
              # a ServiceRespone, it just returns the (possibly invalid and un-saved) record.
              raise ActiveRecord::RecordInvalid.new(created_oauth_app) unless created_oauth_app.persisted? # rubocop:disable Style/RaiseArgs -- We want to directly use ActiveRecord::RecordInvalid.new(created_oauth_app) so it preserves the record attribute of the exception

              application_settings.update!(workspaces_oauth_application: created_oauth_app)
              should_expire_cache = true
            end

            # note: This needs to happen outside the transaction, but only if we actually changed something
            ::Gitlab::CurrentSettings.expire_current_application_settings if should_expire_cache
          end

          # In case the app already existed, use the <= operator to ensure that the attributes are a subset of the
          # existing application attributes to ensure that no admin user has manually changed the application attributes
          unless oauth_application_attributes.stringify_keys <= oauth_application.attributes
            oauth_application.update!(oauth_application_attributes)
          end

          context.merge(workspaces_oauth_application: oauth_application)
        end

        # @return [Authn::OauthApplication]
        def self.oauth_application
          application_settings.workspaces_oauth_application
        end

        # @return [ApplicationSetting]
        def self.application_settings
          ::Gitlab::CurrentSettings.current_application_settings
        end

        private_class_method :oauth_application, :application_settings
      end
    end
  end
end
