# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class Creator
        include CreateConstants
        include Messages

        RANDOM_STRING_LENGTH = 6

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.create(context)
          model_errors = nil

          updated_value = ApplicationRecord.transaction do
            initial_result = Gitlab::Fp::Result.ok(context)

            result =
              initial_result
                .map(CreatorBootstrapper.method(:bootstrap))
                .and_then(PersonalAccessTokenCreator.method(:create))
                .and_then(WorkspaceCreator.method(:create))
                .and_then(WorkspaceVariablesCreator.method(:create))
                # NOTE: Even though DesiredConfig::Main is a nested ROP chain, it is namespaced as a peer to
                #       Creator namespace, to avoid excessive filesystem/namespace nesting.
                #       We need to call it here after the Workspace record is created, because the desired_config field
                #       JSON has some attributes which contain the Workspace record ID.
                .map(DesiredConfig::Main.method(:main))
                .and_then(WorkspaceAgentkStateCreator.method(:create))

            case result
            in { err: PersonalAccessTokenModelCreateFailed |
              WorkspaceModelCreateFailed |
              WorkspaceVariablesModelCreateFailed |
              WorkspaceAgentkStateCreateFailed => message
            }
              model_errors = message.content[:errors]
              raise ActiveRecord::Rollback
            else
              result.unwrap
            end
          end

          if model_errors.present?
            return Gitlab::Fp::Result.err(WorkspaceCreateFailed.new({ errors: model_errors, context: context }))
          end

          Gitlab::Fp::Result.ok(updated_value)
        end
      end
    end
  end
end
