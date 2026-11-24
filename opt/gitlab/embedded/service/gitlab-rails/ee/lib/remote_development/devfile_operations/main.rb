# frozen_string_literal: true

module RemoteDevelopment
  module DevfileOperations
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
            .and_then(DevfileProcessor.method(:validate))
            # NOTE: Gitlab::InternalEvents lazily sets various class-level state due to memoization, therefore we cannot
            #       enforce immutability when it is used.
            .inspect_ok(Observer.method(:observe), enforce_immutability: false)
            .inspect_err(ErrorsObserver.method(:observe), enforce_immutability: false)
            .and_then(ResponseBuilder.method(:build))

        case result
        in { err: AllDevfileErrors => message }
          generate_error_response_from_message(message: message, reason: :bad_request)
        in { ok: DevfileValidateSuccessful => message }
          { status: :success, payload: message.content }
        else
          raise Gitlab::Fp::UnmatchedResultError.new(result: result)
        end
      end
    end
  end
end
