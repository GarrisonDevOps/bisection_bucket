# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Update
      class Main
        include Messages
        extend Gitlab::Fp::MessageSupport

        # @param [Hash] context
        # @return [Hash]
        # @raise [Gitlab::Fp::UnmatchedResultError]
        def self.main(context)
          initial_result = Gitlab::Fp::Result.ok(context)
          result =
            initial_result
              .and_then(Updater.method(:update))

          case result
          in { err: WorkspaceUpdateFailed => message }
            generate_error_response_from_message(message: message, reason: :bad_request)
          in { ok: WorkspaceUpdateSuccessful => message }
            { status: :success, payload: message.content }
          else
            raise Gitlab::Fp::UnmatchedResultError.new(result: result)
          end
        end
      end
    end
  end
end
