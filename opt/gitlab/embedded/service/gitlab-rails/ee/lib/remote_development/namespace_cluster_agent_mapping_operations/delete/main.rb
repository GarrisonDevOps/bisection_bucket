# frozen_string_literal: true

module RemoteDevelopment
  module NamespaceClusterAgentMappingOperations
    module Delete
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
              .and_then(MappingDeleter.method(:delete))
          case result
          in { err: NamespaceClusterAgentMappingNotFound => message }
            generate_error_response_from_message(message: message, reason: :bad_request)
          in { ok: NamespaceClusterAgentMappingDeleteSuccessful => message }
            { status: :success, payload: message.content }
          else
            raise Gitlab::Fp::UnmatchedResultError.new(result: result)
          end
        end
      end
    end
  end
end
