# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module ServerConfig
      class Main
        include Messages
        extend Gitlab::Fp::MessageSupport

        # @param [Hash] context
        # @return [Hash]
        def self.main(context)
          initial_result = Gitlab::Fp::Result.ok(context)

          result =
            initial_result
              .map(OauthApplicationAttributesGenerator.method(:generate))
              .map(OauthApplicationEnsurer.method(:ensure))
              .map(ValuesExtractor.method(:extract))
              .map(
                # As the final step, return the response_payload content in a WorkspacesServerConfigSuccessful message
                ->(context) do
                  WorkspacesServerConfigSuccessful.new(context.fetch(:response_payload))
                end
              )

          # noinspection RubyMismatchedReturnType -- RubyMine not properly detecting return type of Hash
          case result
          in { ok: WorkspacesServerConfigSuccessful => message }
            # Type-check the payload before returning it
            message.content => {
              api_external_url: String,
              oauth_client_id: String,
              oauth_redirect_url: String
            }
            { status: :success, payload: message.content }

            # NOTE: This ROP chain currently consists of only `map` steps, there are no `and_then` steps. Therefore it
            #       is not possible for anything other than the AgentPrerequisitesSuccessful message from last lambda
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
end
