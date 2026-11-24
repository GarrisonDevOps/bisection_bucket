# frozen_string_literal: true

module RemoteDevelopment
  module AgentPrerequisitesOperations
    class Main
      include Messages
      extend Gitlab::Fp::MessageSupport

      # @param [Hash] context
      # @return [Hash]
      def self.main(context)
        initial_result = Gitlab::Fp::Result.ok(context)

        result =
          initial_result
            .map(ResponseBuilder.method(:build))
            .map(
              # As the final step, return the response_payload content in a WorkspaceReconcileSuccessful message
              ->(context) do
                AgentPrerequisitesSuccessful.new(context.fetch(:response_payload))
              end
            )

        # noinspection RubyMismatchedReturnType -- Expects hash, but Result implements #to_h, so should not be an error
        case result
        in { ok: AgentPrerequisitesSuccessful => message }
          # Type-check the payload before returning it
          message.content => {
            shared_namespace: String
          }
          { status: :success, payload: message.content }

          # NOTE: This ROP chain currently consists of only `map` steps, there are no `and_then` steps. Therefore it
          #       is not possible for anything other than the AgentPrerequisitesSuccessful message from the last lambda
          #       step to be returned. If we ever add an `and_then` step, we should uncomment the else case below, and
          #       add an appropriate spec example named: "when an unmatched error is returned, an exception is raised"
          #
          # else
          #   raise Gitlab::Fp::UnmatchedResultError.new(result: result)
        end
      end
    end
  end
end
