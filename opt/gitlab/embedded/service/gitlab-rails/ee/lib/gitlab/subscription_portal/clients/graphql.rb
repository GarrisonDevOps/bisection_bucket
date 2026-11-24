# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    module Clients
      module Graphql
        extend ActiveSupport::Concern

        CONNECTIVITY_ERROR = 'CONNECTIVITY_ERROR'
        RESCUABLE_HTTP_ERRORS = [
          Gitlab::HTTP::BlockedUrlError,
          HTTParty::Error,
          Errno::ECONNREFUSED,
          Errno::ECONNRESET,
          SocketError,
          Timeout::Error,
          OpenSSL::SSL::SSLError
        ].freeze

        class_methods do
          def activate(activation_code, automated:)
            variables = {
              activationCode: activation_code,
              instanceIdentifier: Gitlab::CurrentSettings.uuid,
              uniqueInstanceId: Gitlab::GlobalAnonymousId.instance_uuid,
              automated: automated,
              gitlabVersion: Gitlab::VERSION,
              hostname: Gitlab.config.gitlab.host
            }

            query = <<~GQL
              mutation(
                $activationCode: String!,
                $instanceIdentifier: String!,
                $uniqueInstanceId: String!,
                $automated: Boolean!,
                $gitlabVersion: String!,
                $hostname: String!
              ) {
                cloudActivationActivate(
                  input: {
                    activationCode: $activationCode,
                    instanceIdentifier: $instanceIdentifier,
                    uniqueInstanceId: $uniqueInstanceId,
                    automated: $automated,
                    gitlabVersion: $gitlabVersion,
                    hostname: $hostname
                  }
                ) {
                  licenseKey
                  futureSubscriptions {
                    cloudLicenseEnabled
                    offlineCloudLicenseEnabled
                    plan
                    company
                    email
                    name
                    startsAt
                    expiresAt
                    usersInLicenseCount
                  }
                  newSubscription
                  errors
                }
              }
            GQL

            response = execute_graphql_query(
              { query: query, variables: variables }
            )

            return error(CONNECTIVITY_ERROR) unless response[:success]

            response = response.dig(:data, 'data', 'cloudActivationActivate')

            if response['errors'].blank?
              future_subscriptions = Array(response['futureSubscriptions']).each do |future_subscription_hash|
                future_subscription_hash.deep_transform_keys!(&:underscore)
              end

              {
                success: true,
                license_key: response['licenseKey'],
                future_subscriptions: future_subscriptions,
                new_subscription: response['newSubscription']
              }
            else
              error(response['errors'])
            end
          rescue *RESCUABLE_HTTP_ERRORS => e
            Gitlab::ErrorTracking.log_exception(e)
            error(CONNECTIVITY_ERROR)
          end

          def subscription_seat_usage_alerts_eligibility(namespace_id)
            return error('Must provide a namespace ID') unless namespace_id

            query = <<~GQL
              query($namespaceId: ID!) {
                subscription(namespaceId: $namespaceId) {
                  isEligibleForSeatUsageAlerts
                }
              }
            GQL

            response = execute_graphql_query({ query: query, variables: { namespaceId: namespace_id } })

            if response[:success]
              {
                success: true,
                eligible_for_seat_usage_alerts: response.dig(:data, 'data', 'subscription',
                  'isEligibleForSeatUsageAlerts')
              }
            else
              error(response.dig(:data, :errors))
            end
          rescue *RESCUABLE_HTTP_ERRORS => e
            Gitlab::ErrorTracking.log_exception(e)

            error(CONNECTIVITY_ERROR)
          end

          def subscription_next_term_start_date(namespace_id)
            return error('Must provide a namespace ID') unless namespace_id

            query = <<~GQL
              query($namespaceId: ID!) {
                subscription(namespaceId: $namespaceId) {
                  nextTermStartDate
                }
              }
            GQL

            response = execute_graphql_query({ query: query, variables: { namespaceId: namespace_id } })

            if response[:success]
              {
                success: true,
                next_term_start_date: response.dig(:data, 'data', 'subscription', 'nextTermStartDate')
              }
            else
              error(response.dig(:data, :errors))
            end
          end

          def get_plans(tags:)
            query = <<~GQL
            query getPlans($tags: [PlanTag!]) {
              plans(planTags: $tags) {
                id
              }
            }
            GQL

            response = http_post('graphql', admin_headers, { query: query, variables: { tags: tags } })[:data]

            if response['errors'].blank? && (data = response.dig('data', 'plans'))
              { success: true, data: data }
            else
              track_error(query, response)

              error(response['errors'])
            end
          end

          def filter_purchase_eligible_namespaces(namespaces, plan_id: nil, any_self_service_plan: nil)
            query = <<~GQL
            query FilterEligibleNamespaces($namespaces: [GitlabNamespaceInput!]!, $planId: ID, $eligibleForPurchase: Boolean) {
              namespaceEligibility(namespaces: $namespaces, planId: $planId, eligibleForPurchase: $eligibleForPurchase) {
                id
              }
            }
            GQL

            namespace_data = namespaces.map do |namespace|
              {
                id: namespace.id,
                parentId: namespace.parent_id,
                plan: namespace.actual_plan_name,
                trial: !!namespace.trial?,
                kind: namespace.kind,
                membersCountWithDescendants: namespace.group_namespace? ? namespace.users_with_descendants.count : nil
              }
            end

            response = http_post(
              'graphql',
              admin_headers,
              { query: query, variables: {
                namespaces: namespace_data,
                planId: plan_id,
                eligibleForPurchase: any_self_service_plan
              } }
            )[:data]

            data = response.dig('data', 'namespaceEligibility')

            # Return success for empty arrays (valid filter result), but fail for nil data
            if response['errors'].blank? && !data.nil?
              { success: true, data: data }
            else
              track_error(query, response)

              error(response['errors'])
            end
          end

          def update_namespace_name(namespace_id, namespace_name)
            variables = {
              namespaceId: namespace_id,
              namespaceName: namespace_name
            }

            query = <<~GQL
              mutation($namespaceId: ID!, $namespaceName: String!) {
                orderNamespaceNameUpdate(
                  input: {
                    namespaceId: $namespaceId,
                    namespaceName: $namespaceName
                  }
                ) {
                  errors
                }
              }
            GQL

            response = execute_graphql_query(
              { query: query, variables: variables }
            )

            parse_errors(response, query_name: 'orderNamespaceNameUpdate').presence || { success: true }
          rescue *RESCUABLE_HTTP_ERRORS => e
            Gitlab::ErrorTracking.log_exception(e)

            error(CONNECTIVITY_ERROR)
          end

          def send_seat_overage_notification(group:, max_seats_used:)
            query = <<~GQL
              mutation($namespaceId: Int!, $maxSeatsUsed: Int!, $groupOwners: [GitlabEmailsUserInput!]!) {
                sendSeatOverageNotificationEmail(input: {
                  glNamespaceId: $namespaceId,
                  maxSeatsUsed: $maxSeatsUsed,
                  groupOwners: $groupOwners
                }) {
                  errors
                }
              }
            GQL

            owners_data = group.map_member_user(access_level: GroupMember::OWNER) do |owner|
              { id: owner.id, email: owner.notification_email_for(group), fullName: owner.name }
            end

            response = execute_graphql_query(
              {
                query: query,
                variables: { namespaceId: group.id, maxSeatsUsed: max_seats_used, groupOwners: owners_data }
              }
            )

            parse_errors(response, query_name: 'sendSeatOverageNotificationEmail').presence || { success: true }
          rescue *RESCUABLE_HTTP_ERRORS => e
            Gitlab::ErrorTracking.log_exception(e)

            error(CONNECTIVITY_ERROR)
          end

          def send_seat_overage_notification_batch(namespaces)
            query = <<~GQL
              mutation($namespaces: [NamespaceSeatOverageInput!]) {
                sendSeatOverageNotificationEmail(input: {
                  namespaces: $namespaces
                }) {
                  errors
                }
              }
            GQL

            response = execute_graphql_query(
              query: query,
              variables: { namespaces: namespaces }
            )

            parse_errors(response, query_name: 'sendSeatOverageNotificationEmail').presence || { success: true }
          rescue *RESCUABLE_HTTP_ERRORS => e
            Gitlab::ErrorTracking.log_exception(e)

            error(CONNECTIVITY_ERROR)
          end

          def get_cloud_connector_access_data(license_key)
            query = <<~GQL
            query cloudConnectorAccess($licenseKey: String!, $gitlabVersion: String!) {
              cloudConnectorAccess(licenseKey: $licenseKey, gitlabVersion: $gitlabVersion) {
                serviceToken {
                  token
                  expiresAt
                }
                catalog
              }
            }
            GQL

            response = http_post('graphql',
              json_headers.merge(::CloudConnector.headers(nil)),
              {
                query: query,
                variables: {
                  licenseKey: license_key,
                  gitlabVersion: Gitlab::VERSION
                }
              }
            )[:data]

            if response['errors'].blank?
              token = response.dig('data', 'cloudConnectorAccess', 'serviceToken', 'token')
              expires_at = response.dig('data', 'cloudConnectorAccess', 'serviceToken', 'expiresAt')
              catalog = response.dig('data', 'cloudConnectorAccess', 'catalog')
              {
                success: true,
                token: token,
                expires_at: expires_at,
                catalog: catalog
              }
            else
              track_error(query, response)

              error(response['errors'])
            end
          end

          private

          def execute_graphql_query(params)
            response = ::Gitlab::HTTP.post(
              graphql_endpoint,
              headers: admin_headers,
              body: params.to_json
            )

            parse_response(response)
          end

          def graphql_endpoint
            ::Gitlab::Routing.url_helpers.subscription_portal_graphql_url
          end

          def track_error(query, response)
            Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
              SubscriptionPortal::Client::ResponseError.new("Received an error from CustomerDot"),
              query: query,
              response: response
            )
          end

          def parse_errors(response, query_name: nil)
            return error(CONNECTIVITY_ERROR) unless response[:success]

            errors = [
              response.dig(:data, 'errors'),
              response.dig(:data, 'data', query_name, 'errors')
            ]

            errors = errors.flat_map(&:presence).compact

            error(errors) if errors.any?
          end

          def error(errors = nil)
            {
              success: false,
              errors: errors
            }.compact
          end
        end
      end
    end
  end
end
