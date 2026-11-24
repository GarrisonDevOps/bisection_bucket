# frozen_string_literal: true

# This is based on https://github.com/rmosolgo/graphql-ruby/blob/v1.11.8/lib/graphql/subscriptions/action_cable_subscriptions.rb#L19-L82
# modified to work with our own ActionCableLink client

class GraphqlChannel < ApplicationCable::Channel # rubocop:disable Gitlab/NamespacedClass
  def subscribed
    @subscription_ids = []

    query = GraphQL::Language.escape_single_quoted_newlines(params['query'].to_s)
    variables = Gitlab::Graphql::Variables.new(params['variables']).to_h
    operation_name = params['operationName']

    result = GitlabSchema.execute(
      query,
      context: context,
      variables: variables,
      operation_name: operation_name
    )

    # Track the subscription here so we can remove it
    # on unsubscribe.
    @subscription_ids << result.context[:subscription_id] if result.context[:subscription_id]

    result_hash = result.to_h

    # A subscription without initial data yields a null field. The client
    # would treat that empty result as a subscription event.
    return if result.subscription? && result_hash['errors'].blank? && result_hash['data']&.values&.all?(&:nil?)

    transmit({ result: result_hash, more: result.subscription? })
  end

  def unsubscribed
    return if @subscription_ids.blank?

    @subscription_ids.each do |sid|
      GitlabSchema.subscriptions.delete_subscription(sid)
    end
  end

  rescue_from Gitlab::Graphql::Variables::Invalid do |exception|
    transmit({ errors: [{ message: exception.message }] })
  end

  private

  # Keep in sync with GraphqlController#context so subscriptions get the same context.
  # New objects may also need reloading in `Subscriptions::BaseSubscription` so they are not stale.
  def context
    request_authenticator = Gitlab::Auth::RequestAuthenticator.new(request)
    scope_validator = ::Gitlab::Auth::ScopeValidator.new(current_user, request_authenticator)
    {
      channel: self,
      current_user: current_user,
      current_organization: connection.current_organization,
      is_sessionless_user: false,
      scope_validator: scope_validator,
      access_token: access_token
    }
  end
end

::GraphqlChannel.prepend_mod_with('GraphqlChannel')
