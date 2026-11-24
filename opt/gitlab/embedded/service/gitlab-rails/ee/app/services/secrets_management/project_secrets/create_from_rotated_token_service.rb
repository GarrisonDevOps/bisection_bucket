# frozen_string_literal: true

module SecretsManagement
  module ProjectSecrets
    class CreateFromRotatedTokenService < ProjectBaseService
      include Secrets::ReadMetadataServiceHelpers

      def execute(personal_access_token_id:, name:, environment:, branch:, description: nil)
        # Rotation revokes a live credential, so every caller is gated, not only the mutation.
        # The top-level namespace is the actor so one flag change can cover a whole group.
        if Feature.disabled?(:secrets_manager_pat_rotation, project.root_ancestor)
          return error(_('Feature disabled'), :feature_disabled)
        end

        token = PersonalAccessToken.find_by_id(personal_access_token_id)
        return error(_('Personal access token not found'), :token_not_found) unless token

        unless Ability.allowed?(current_user, :rotate_personal_access_token, token.user)
          return error(_('You are not allowed to rotate this personal access token'), :forbidden)
        end

        # RotateService refuses this too, but without a reason that callers and metrics can tell apart.
        return error(s_('AccessTokens|Token already revoked'), :token_revoked) if token.revoked?

        # Rotating an expired token would turn a dead key into a live one.
        return error(_('Personal access token has expired'), :token_expired) if token.expired?

        # Hold the lease from preflight through the store, so a concurrent secret
        # operation can't make the store fail after the old token is revoked.
        with_exclusive_lease_for(project) do
          rotate_and_store(name: name, description: description, environment: environment, branch: branch, token: token)
        end
      end

      private

      delegate :secrets_manager, to: :project

      def rotate_and_store(token:, **attributes)
        # Rotation revokes the old token and can't be undone, so reject anything cheap
        # that would make the store fail before we ever touch the token.
        invalid = preflight(**attributes)
        return invalid if invalid

        rotation = rotate(token)
        return rotation unless rotation.success?

        store_or_revoke(rotation.payload[:personal_access_token], **attributes)
      end

      def preflight(name:, description:, environment:, branch:)
        unless project.secrets_manager&.active?
          return error(secrets_manager_inactive_response.message, :secrets_manager_inactive)
        end

        unless project.self_and_ancestors_active?
          return error(
            _('You cannot perform write operations on an archived project or a project pending deletion.'),
            :namespace_inactive
          )
        end

        entitlement_error = validate_entitlement(action: 'written')
        return entitlement_error if entitlement_error

        secret = ProjectSecret.new(
          name: name,
          description: description,
          project: project,
          branch: branch,
          environment: environment
        )
        return validation_error(secret) unless secret.valid?

        unless user_capable?(name, BaseSecretsPermission::CAPABILITIES[:create])
          return error(_('You are not allowed to create secrets in this project'), :create_forbidden)
        end

        if secret_exists?(name)
          return error(format(_("A secret named '%{name}' already exists"), name: name), :secret_exists)
        end

        return secrets_limit_exceeded_error if secrets_limit_exceeded?

        nil
      end

      def secret_exists?(name)
        ProjectSecrets::ReadMetadataService.new(project, current_user)
          .execute(name, include_rotation_info: false, write_capability: BaseSecretsPermission::CAPABILITIES[:create])
          .success?
      end

      def secrets_limit_exceeded?
        SecretsManagement::ProjectSecretsCountService.new(project, current_user).secrets_limit_exceeded?
      end

      def rotate(token)
        PersonalAccessTokens::RotateService.new(
          current_user,
          token,
          nil,
          { keep_token_lifetime: true, creation_source: PersonalAccessToken::CREATION_SOURCE_API }
        ).execute
      end

      # The new token value exists only in memory. If it can't be stored, revoke it
      # rather than leave an active token that nobody can retrieve.
      def store_or_revoke(new_token, **attributes)
        result = store(value: new_token.token, **attributes)
        return result if result.success?

        revoked = revoke(new_token)
        log_store_failure(new_token, revoked: revoked, reason: result.reason)

        message = if revoked
                    _('The token was rotated, but the new value could not be stored, so it was revoked. ' \
                      'Create a new token manually. %{message}')
                  else
                    _('The token was rotated, but the new value could not be stored or revoked. ' \
                      'Revoke the token named %{token_name} manually. %{message}')
                  end

        error(format(message, message: result.message, token_name: new_token.name), :store_failed)
      rescue StandardError => error
        # The exception message can carry request details, so only its occurrence is logged.
        log_store_failure(new_token, revoked: revoke_after_exception(new_token), reason: :exception)
        raise error
      end

      # A failing cleanup must not hide the store error or skip the log line.
      def revoke_after_exception(new_token)
        revoke(new_token)
      rescue StandardError => revoke_error
        Gitlab::ErrorTracking.track_exception(revoke_error, personal_access_token_id: new_token.id,
          project_id: project.id)
        nil
      end

      def revoke(new_token)
        result = PersonalAccessTokens::RevokeService.new(current_user, token: new_token).execute
        return true if result.success?

        Gitlab::ErrorTracking.track_exception(
          StandardError.new(result.message),
          personal_access_token_id: new_token.id,
          project_id: project.id
        )
        false
      end

      # The old token is already revoked here, so the user may be left without a working token.
      def log_store_failure(new_token, revoked:, reason:)
        Gitlab::AppJsonLogger.warn(
          Labkit::Fields::CLASS_NAME => self.class.name,
          message: 'Rotated personal access token could not be stored as a project secret',
          Labkit::Fields::GL_PROJECT_ID => project.id,
          personal_access_token_id: new_token.id,
          revoked: revoked,
          store_error_reason: reason
        )
      end

      def store(name:, value:, environment:, branch:, description:)
        CreateService.new(project, current_user).execute_without_lease(
          name: name,
          value: value,
          environment: environment,
          branch: branch,
          description: description
        )
      end

      def validation_error(secret)
        ServiceResponse.error(message: secret.errors.full_messages.to_sentence, payload: { secret: secret },
          reason: :invalid_secret)
      end

      def secrets_limit_exceeded_error
        error(_('Maximum number of secrets for this project has been reached'), :secrets_limit_exceeded)
      end

      def error(message, reason)
        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
