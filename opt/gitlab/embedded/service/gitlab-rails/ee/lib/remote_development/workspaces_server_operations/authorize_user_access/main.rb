# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module AuthorizeUserAccess
      class Main
        include Messages
        extend Gitlab::Fp::MessageSupport

        # @param [Hash] context
        # @return [Hash]
        def self.main(context)
          initial_result = Gitlab::Fp::Result.ok(context)

          result =
            initial_result
              .and_then(WorkspaceHostParser.method(:parse_workspace_host))
              .and_then(WorkspaceFinder.method(:find_workspace))
              .and_then(Authorizer.method(:authorize))
              .map(
                # As the final step, return the response_payload content in a WorkspaceAuthorizeUserAccessSuccessful
                # message
                ->(context) do
                  WorkspaceAuthorizeUserAccessSuccessful.new(context.fetch(:response_payload))
                end
              )

          # noinspection RubyMismatchedReturnType -- RubyMine not properly detecting return type of Hash
          case result
          in { ok: WorkspaceAuthorizeUserAccessSuccessful => message }
            # Type-check the payload before returning it
            message.content => {
              status: String,
              info: Hash
            }
            { status: :success, payload: message.content }
          in { err: WorkspaceAuthorizeUserAccessFailed => message }
            # Type-check the payload before returning it
            message.content => {
              status: String
            }
            { status: :success, payload: message.content.merge(info: {}) }
          else
            raise Gitlab::Fp::UnmatchedResultError.new(result: result)
          end
        end
      end
    end
  end
end
