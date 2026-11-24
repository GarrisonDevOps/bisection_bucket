# frozen_string_literal: true

module Security
  module Orchestration
    class CreateBotService
      attr_reader :project, :current_user, :skip_authorization

      def initialize(project, current_user, skip_authorization: false)
        @project = project
        @current_user = current_user
        @skip_authorization = skip_authorization
      end

      def execute
        return if project.security_policy_bot.present?

        unless skip_authorization || Ability.allowed?(current_user, :admin_project_member, project)
          log_bot_creation_status('User not authorized to create security policy bot')
          raise Gitlab::Access::AccessDeniedError
        end

        User.transaction do
          log_bot_creation_status('Creating security policy bot user')

          response = ::Users::CreateBotService.new(
            current_user,
            bot_user_params
          ).execute

          if response.success?
            bot_user = response.payload[:user]

            Gitlab::Database::QueryAnalyzers::PreventCrossDatabaseModification.temporary_ignore_tables_in_transaction(
              %w[members notification_settings events projects], url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/424290'
            ) do
              # Check if add_guest returns a result we can check
              result = if skip_authorization
                         project.add_guest(bot_user)
                       else
                         project.add_guest(bot_user, current_user: current_user)
                       end

              # Log the result of adding the guest
              if result && result.valid?
                log_bot_creation_status('Successfully created security policy bot user',
                  bot_user_id: bot_user.id, bot_username: bot_user.username)
                log_bot_creation_status('Successfully added security policy bot as guest to project')
              elsif result && result.respond_to?(:errors)
                log_bot_creation_status('Failed to add security policy bot as guest to project',
                  "add_guest did not complete successfully: #{result.errors.full_messages.to_sentence}")
              else
                log_bot_creation_status('Failed to add security policy bot as guest to project', 'unknown')
              end

              result
            end
          else
            log_bot_creation_status('Failed to create security policy bot user', response.message)
          end
        end
      end

      private

      def log_bot_creation_status(message, reason = nil)
        Gitlab::AppJsonLogger.info(
          event: 'security_policy_bot_creation',
          project_id: project.id,
          project_path: project.full_path,
          user_id: current_user&.id,
          class: self.class.name,
          message: message,
          reason: reason
        )
      end

      def bot_user_params
        {
          name: 'GitLab Security Policy Bot',
          email: username_and_email_generator.email,
          username: username_and_email_generator.username,
          user_type: :security_policy_bot,
          skip_confirmation: true, # Bot users should always have their emails confirmed.
          external: true,
          avatar: Users::Internal.bot_avatar(image: 'security-bot.png'),
          organization_id: project.organization_id,
          private_profile: true
        }
      end

      def username_and_email_generator
        Gitlab::Utils::UsernameAndEmailGenerator.new(
          username_prefix: "gitlab_security_policy_project_#{project.id}_bot",
          email_domain: "noreply.#{Gitlab.config.gitlab.host}"
        )
      end
    end
  end
end
