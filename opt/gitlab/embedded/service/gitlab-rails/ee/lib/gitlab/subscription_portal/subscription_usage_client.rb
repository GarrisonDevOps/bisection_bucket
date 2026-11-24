# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    class SubscriptionUsageClient < Client
      include ::Gitlab::Utils::StrongMemoize

      class ResponseError < StandardError
        # The classified failure (:undefined_field, :server_error, :rate_limited, :disabled,
        # :unavailable, :malformed_response, :no_cdot_subscription_found, :error) so a caller
        # can act on it without re-reading the response. retry_after is the 429 Retry-After
        # in whole seconds, nil when absent or unusable.
        attr_reader :reason, :retry_after

        def initialize(message = nil, reason: nil, retry_after: nil)
          @reason = reason
          @retry_after = retry_after
          super(message)
        end
      end

      GET_METADATA_QUERY = <<~GQL
        query subscriptionUsageMetadata(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $gitlabVersion: String!,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              startDate
              endDate
              enabled
              isOutdatedClient(gitlabVersion: $gitlabVersion)
              lastEventTransactionAt
              overageTermsAccepted
              canAcceptOverageTerms
              dapPromoEnabled
              usageDashboardPath
            }
          }
        }
      GQL

      GET_PAID_TIER_TRIAL_QUERY = <<~GQL
        query subscriptionUsagePaidTierTrial(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              paidTierTrial {
                isActive
                dailyUsage {
                  date
                  creditsUsed
                }
              }
            }
          }
        }
      GQL

      GET_SUBSCRIPTION_USAGE_QUERY = <<~GQL
        query subscriptionUsage(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $sort: DailyUsageSort,
          $limit: Int,
          $flowTypes: [String!]
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate, flowTypes: $flowTypes) {
              creditsUsed
              dailyAverage
              dailyUsage(sort: $sort, limit: $limit) {
                date
                creditsUsed
              }
            }
          }
        }
      GQL

      GET_NON_BILLABLE_USAGE_QUERY = <<~GQL
        query nonBillableUsage(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $flowTypes: [String!]
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate, flowTypes: $flowTypes) {
              nonBillableUsage {
                productId
                skipReason
                totalCreditsUsed
                dailyUsage {
                  date
                  creditsUsed
                }
              }
            }
          }
        }
      GQL

      # Must match Types::Subscriptions::GitlabCredits::UsageType::NON_BILLABLE_USAGE_UNAVAILABLE_CODE
      # in CustomersDot.
      NON_BILLABLE_USAGE_UNAVAILABLE_CODE = "NON_BILLABLE_USAGE_UNAVAILABLE"

      # Above CustomersDot's 20s ClickHouse max_execution_time, so a slow query reaches us
      # as its 500 (:server_error, status logged) instead of our own Net::ReadTimeout.
      CLICKHOUSE_QUERY_READ_TIMEOUT = 25

      # v2 pull: CustomersDot reports the sessions whose total changed since `updatedAfter`.
      # No startDate/endDate: `creditsUsed` is a lifetime total.
      GET_SESSIONS_QUERY = <<~GQL
        query sessionCreditsV2(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $updatedAfter: ISO8601DateTimeMicro!,
          $first: Int,
          $after: String
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId) {
              sessionsSyncedAt
              sessions(updatedAfter: $updatedAfter, first: $first, after: $after) {
                nodes {
                  workflowId
                  creditsUsed
                  modelsUsed
                  updatedAt
                  creditsByModel {
                    model
                    creditsUsed
                  }
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
              }
            }
          }
        }
      GQL

      # CustomersDot caps `first` at 1000 (customers-gitlab-com!17421).
      SESSIONS_PAGE_SIZE = 1000
      # CustomersDot's kill switches (`usage_billing_disable_sessions_api` for this field) raise
      # with this code.
      KILL_SWITCH_ERROR_CODE = 'FEATURE_DISABLED'
      # A ClickHouse timeout on CustomersDot is a GraphQL error with HTTP 200, not a 5xx.
      SESSIONS_UNAVAILABLE_MESSAGE = "sessions is temporarily unavailable. Please try again later."
      # Every field GET_SESSIONS_QUERY selects, so a missing one is recognised as ours.
      SESSIONS_QUERY_FIELDS = %w[
        sessions sessionsSyncedAt workflowId creditsUsed modelsUsed updatedAt creditsByModel model
      ].freeze

      # GitLab.com only: the root namespaces CustomersDot billed for a session changed since
      # `updatedAfter`, wherever the session ran. Authenticated by the admin token.
      GET_SESSION_NAMESPACES_QUERY = <<~GQL
        query sessionNamespaces(
          $updatedAfter: ISO8601DateTimeMicro!,
          $first: Int,
          $after: String
        ) {
          sessionNamespaces(updatedAfter: $updatedAfter, first: $first, after: $after) {
            nodes {
              rootNamespaceId
              updatedAt
            }
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
      GQL

      SESSION_NAMESPACES_PAGE_SIZE = 10_000
      SESSION_NAMESPACES_UNAVAILABLE_MESSAGE =
        "sessionNamespaces is temporarily unavailable. Please try again later."
      SESSION_NAMESPACES_QUERY_FIELDS = %w[sessionNamespaces rootNamespaceId updatedAt].freeze

      GET_MONTHLY_WAIVER_QUERY = <<~GQL
        query subscriptionUsageMonthlyWaiver(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              monthlyWaiver {
                creditsUsed
                totalCredits
                dailyUsage {
                  date
                  creditsUsed
                }
              }
            }
          }
        }
      GQL

      GET_MONTHLY_COMMITMENT_QUERY = <<~GQL
        query subscriptionUsageMonthlyCommitment(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              monthlyCommitment {
                totalCredits
                creditsUsed
                dailyUsage {
                  date
                  creditsUsed
                }
              }
            }
          }
        }
      GQL

      GET_OVERAGE_QUERY = <<~GQL
        query subscriptionUsageOverage(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              overage {
                isAllowed
                creditsUsed
                dailyUsage {
                  date
                  creditsUsed
                }
              }
            }
          }
        }
      GQL

      GET_USER_EVENTS_QUERY = <<~GQL
        query subscriptionUsageUserEvents(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $userIds: [Int!]!,
          $flowTypes: [String],
          $first: Int,
          $last: Int,
          $after: String,
          $before: String
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              usersUsage {
                users(userIds: $userIds) {
                  events(first: $first, last: $last, before: $before, after: $after, flowTypes: $flowTypes) {
                    nodes {
                      timestamp
                      eventType
                      flowType
                      projectId
                      namespaceId
                      creditsUsed
                      sessionId
                      showSessionLink
                    }
                    pageInfo {
                      hasNextPage
                      hasPreviousPage
                      startCursor
                      endCursor
                    }
                  }
                }
              }
            }
          }
        }
      GQL

      # Leaves out the deprecated `eventType` to stay under CustomersDot's query complexity
      # cap for license-key requests (200): the two new fields over a 20-row page cost 40.
      GET_USER_EVENTS_WITH_NON_BILLABLE_QUERY = <<~GQL
        query subscriptionUsageUserEventsWithNonBillable(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $userIds: [Int!]!,
          $flowTypes: [String],
          $first: Int,
          $last: Int,
          $after: String,
          $before: String
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              usersUsage {
                users(userIds: $userIds) {
                  events(
                    first: $first, last: $last, before: $before, after: $after, flowTypes: $flowTypes,
                    includeNonBillable: true
                  ) {
                    nodes {
                      timestamp
                      flowType
                      projectId
                      namespaceId
                      creditsUsed
                      sessionId
                      showSessionLink
                      billable
                      skipReason
                    }
                    pageInfo {
                      hasNextPage
                      hasPreviousPage
                      startCursor
                      endCursor
                    }
                  }
                }
              }
            }
          }
        }
      GQL

      GET_USED_FLOW_TYPES_WITH_NON_BILLABLE_QUERY = <<~GQL
        query subscriptionUsageUsedFlowTypesWithNonBillable(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $userIds: [Int!]!
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              usersUsage {
                users(userIds: $userIds) {
                  usedFlowTypes(includeNonBillable: true) {
                    id
                    title
                  }
                }
              }
            }
          }
        }
      GQL

      GET_USED_FLOW_TYPES_QUERY = <<~GQL
        query subscriptionUsageUsedFlowTypes(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $userIds: [Int!]!
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              usersUsage {
                users(userIds: $userIds) {
                  usedFlowTypes {
                    id
                    title
                  }
                }
              }
            }
          }
        }
      GQL

      GET_USER_DAILY_USAGE_QUERY = <<~GQL
        query subscriptionUsageDailyUsageForUserId(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $userIds: [Int!]!,
          $flowTypes: [String]
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              usersUsage {
                users(userIds: $userIds) {
                  dailyUsage(flowTypes: $flowTypes) {
                    date
                    creditsUsed
                  }
                }
              }
            }
          }
        }
      GQL

      GET_USER_NON_BILLABLE_USAGE_QUERY = <<~GQL
        query subscriptionUsageNonBillableUsageForUserId(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $userIds: [Int!]!,
          $flowTypes: [String]
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              usersUsage {
                users(userIds: $userIds) {
                  nonBillableUsage(flowTypes: $flowTypes) {
                    productId
                    skipReason
                    totalCreditsUsed
                    dailyUsage {
                      date
                      creditsUsed
                    }
                  }
                }
              }
            }
          }
        }
      GQL

      GET_USERS_USAGE_QUERY = <<~GQL
        query subscriptionUsageForUserIds(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $userIds: [Int!]!,
          $flowTypes: [String!]
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate, flowTypes: $flowTypes) {
              usersUsage {
                users(userIds: $userIds) {
                  userId
                  totalCredits
                  creditsUsed
                  totalCreditsUsed
                  monthlyCommitmentCreditsUsed
                  monthlyWaiverCreditsUsed
                  overageCreditsUsed
                  paidTierTrialCreditsUsed
                  nonBillableCreditsUsed
                }
              }
            }
          }
        }
      GQL

      GET_CONSUMERS_QUERY = <<~GQL
        query subscriptionUsageForConsumers(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $sort: GitlabCreditsConsumerSort,
          $first: Int,
          $last: Int,
          $after: String,
          $before: String,
          $flowTypes: [String!]
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate, flowTypes: $flowTypes) {
              usersUsage {
                consumers(
                  sort: $sort
                  first: $first
                  last: $last
                  after: $after
                  before: $before
                ) {
                  nodes {
                    userId
                    totalCredits
                    creditsUsed
                    totalCreditsUsed
                    monthlyCommitmentCreditsUsed
                    monthlyWaiverCreditsUsed
                    overageCreditsUsed
                    paidTierTrialCreditsUsed
                    nonBillableCreditsUsed
                    entityType
                  }
                  pageInfo {
                    hasNextPage
                    hasPreviousPage
                    startCursor
                    endCursor
                  }
                }
              }
            }
          }
        }
      GQL

      # If CustomersDot rejects the full page, retry with only the fields the listing needs;
      # the per-wallet breakdown on `usage` is null for that page.
      CONSUMERS_BREAKDOWN_FIELDS = %w[
        totalCredits
        creditsUsed
        monthlyCommitmentCreditsUsed
        monthlyWaiverCreditsUsed
        overageCreditsUsed
        paidTierTrialCreditsUsed
      ].freeze
      GET_CONSUMERS_WITHOUT_BREAKDOWN_QUERY =
        GET_CONSUMERS_QUERY.gsub(/^\s+(#{CONSUMERS_BREAKDOWN_FIELDS.join('|')})\n/, '').freeze

      GET_USERS_USAGE_STATS_QUERY = <<~GQL
        query subscriptionUsageUsersStats(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $flowTypes: [String!]
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate, flowTypes: $flowTypes) {
              usersUsage {
                totalActiveUsers
                totalUsersUsingCredits
                totalUsersUsingMonthlyCommitment
                totalUsersUsingOverage
                creditsUsed
                dailyUsage {
                  date
                  creditsUsed
                }
              }
            }
          }
        }
      GQL

      GET_TRIAL_USAGE_QUERY = <<~GQL
        query trialUsage(
          $namespaceId: ID,
          $licenseKey: String
        ) {
          trialUsage(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            activeTrial {
              startDate
              endDate
            }
            usersUsage {
              creditsUsed
              totalUsersUsingCredits
            }
          }
        }
      GQL

      GET_TRIAL_USAGE_FOR_USER_IDS_QUERY = <<~GQL
        query trialUsageForUserIds(
          $namespaceId: ID,
          $licenseKey: String,
          $userIds: [Int!]!
        ) {
          trialUsage(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            usersUsage {
              users(userIds: $userIds) {
                userId
                totalCredits
                creditsUsed
              }
            }
          }
        }
      GQL

      GET_BUDGET_CAPS_QUERY = <<~GQL
        query budgetCaps(
          $namespaceId: ID,
          $licenseKey: String,
          $entityIds: [String!],
          $first: Int,
          $last: Int,
          $after: String,
          $before: String
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            budgetControls {
              subscription {
                subscriptionName
                subscriptionCap
                subscriptionCapEnabled
                flatUserCap
                flatUserCapEnabled
              }
              userBudgetCapOverrides(
                entityIds: $entityIds,
                first: $first,
                last: $last,
                after: $after,
                before: $before
              ) {
                nodes {
                  entityId
                  cap
                  capEnabled
                  selfManagedInstanceActivationId
                  createdAt
                  updatedAt
                }
                pageInfo {
                  hasNextPage
                  hasPreviousPage
                  startCursor
                  endCursor
                }
              }
            }
          }
        }
      GQL

      UPSERT_USER_BUDGET_CAPS_MUTATION = <<~GQL
        mutation upsertUserBudgetCapsBulk(
          $input: UpsertUserBudgetCapsBulkInput!
        ) {
          upsertUserBudgetCapsBulk(input: $input) {
            userBudgetCapOverrides {
              entityId
              cap
              capEnabled
              selfManagedInstanceActivationId
            }
            errors
          }
        }
      GQL

      UPSERT_FLAT_USER_CAP_MUTATION = <<~GQL
        mutation upsertBudgetCapSubscription(
          $input: UpsertBudgetCapSubscriptionInput!
        ) {
          upsertBudgetCapSubscription(input: $input) {
            subscriptionBudgetCap {
              subscriptionName
              flatUserCap
              flatUserCapEnabled
            }
            errors
          }
        }
      GQL

      GET_PRODUCTS_QUERY = <<~GQL
        query subscriptionUsageProducts(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              products {
                id
                title
                creditsUsed
                flowTypes {
                  id
                  title
                }
              }
            }
          }
        }
      GQL

      GET_BLOCKED_STATUSES_QUERY = <<~GQL
        query subscriptionBlockedStatuses(
          $instanceId: String,
          $namespaceId: ID,
          $licenseKey: String,
          $startDate: ISO8601Date,
          $endDate: ISO8601Date,
          $entityIds: [String!]!
        ) {
          subscription(namespaceId: $namespaceId, licenseKey: $licenseKey) {
            gitlabCreditsUsage(instanceId: $instanceId, startDate: $startDate, endDate: $endDate) {
              blockedStatuses(entityIds: $entityIds) {
                nodes {
                  entityId
                  blocked
                  capType
                }
              }
            }
          }
        }
      GQL

      # Initialize the client with the provided parameters that will be used later
      # to make API calls to the subscription portal
      #
      # @param namespace_id [Integer] The ID of the namespace, used when in GitLab.com
      # @param license_key [String] The license key to use for authentication in Self-Managed instances
      # @param start_date [String] The start date of the usage period (ISO 8601 format)
      # @param end_date [String] The end date of the usage period (ISO 8601 format)
      def initialize(
        namespace_id: nil,
        license_key: nil,
        start_date: Date.current.beginning_of_month.iso8601,
        end_date: Date.current.end_of_month.iso8601
      )
        @namespace_id = namespace_id
        @license_key = license_key
        @start_date = start_date
        @end_date = end_date
      end

      def get_metadata
        response = execute_graphql_query(
          query: GET_METADATA_QUERY,
          extra_variables: { gitlabVersion: Gitlab::VERSION }
        )

        if unsuccessful_response?(response)
          error(GET_METADATA_QUERY, response)
        else
          {
            success: true,
            subscriptionUsage: response.dig(:data, :subscription, :gitlabCreditsUsage)
          }
        end
      end
      strong_memoize_attr :get_metadata

      def get_subscription_usage(args = {})
        strong_memoize_with(:get_subscription_usage, args) do
          response = execute_graphql_query(
            query: GET_SUBSCRIPTION_USAGE_QUERY,
            extra_variables: {
              sort: args[:sort]&.upcase,
              limit: args[:limit],
              flowTypes: args[:flow_types].presence
            }.compact
          )

          if unsuccessful_response?(response)
            error(GET_SUBSCRIPTION_USAGE_QUERY, response)
          else
            {
              success: true,
              subscriptionUsage: response.dig(:data, :subscription, :gitlabCreditsUsage)
            }
          end
        end
      end

      def get_non_billable_usage(flow_types: nil)
        strong_memoize_with(:get_non_billable_usage, flow_types) do
          response = execute_graphql_query(
            query: GET_NON_BILLABLE_USAGE_QUERY,
            extra_variables: { flowTypes: flow_types.presence }.compact,
            read_timeout: CLICKHOUSE_QUERY_READ_TIMEOUT
          )

          if non_billable_usage_unavailable_error?(response)
            Gitlab::AppLogger.warn(
              Labkit::Fields::CLASS_NAME => self.class.name,
              Labkit::Fields::LOG_MESSAGE => "CustomersDot could not read nonBillableUsage"
            )

            { success: false, nonBillableUsage: nil }
          elsif unsuccessful_response?(response)
            error(GET_NON_BILLABLE_USAGE_QUERY, response)
          else
            {
              success: true,
              nonBillableUsage: response.dig(:data, :subscription, :gitlabCreditsUsage, :nonBillableUsage)
            }
          end
        end
      end

      # One page of changed sessions. Not memoized: the caller walks successive pages.
      def get_sessions(updated_after:, first: SESSIONS_PAGE_SIZE, after: nil)
        response = execute_cdot_graphql(
          query: GET_SESSIONS_QUERY,
          variables: {
            instanceId: Gitlab::GlobalAnonymousId.instance_id,
            namespaceId: namespace_id,
            licenseKey: license_key,
            updatedAfter: updated_after.getutc.iso8601(6),
            first: first,
            after: after.presence
          }.compact,
          read_timeout: CLICKHOUSE_QUERY_READ_TIMEOUT
        )

        # The reason only names the failure in the log line; every failure raises.
        reason = query_failure_reason(response, fields: SESSIONS_QUERY_FIELDS,
          unavailable_message: SESSIONS_UNAVAILABLE_MESSAGE)
        # The caller waits a 429 out and retries, so each attempt is logged, never reported.
        if reason == :rate_limited
          log_warning("CustomersDot sessions query failed: #{reason}", response)
          raise ResponseError.new("Received an error from CustomerDot", reason: reason,
            retry_after: response[:retry_after])
        end

        if reason
          return log_query_failure("CustomersDot sessions query failed: #{reason}", GET_SESSIONS_QUERY, response,
            reason: reason)
        end

        data = response[:data]
        # No subscription is a fact about the namespace, not a CustomersDot degradation: logged, not reported.
        if data.is_a?(Hash) && data.key?(:subscription) && data[:subscription].nil?
          log_warning("CustomersDot has no subscription for this namespace", response)
          raise ResponseError.new("No CustomersDot subscription for namespace", reason: :no_cdot_subscription_found)
        end

        usage = response.dig(:data, :subscription, :gitlabCreditsUsage)
        connection = usage&.dig(:sessions)

        # A null connection with no error is not an empty page: success here would let
        # the caller advance its cursor past a window it never read.
        if connection.nil?
          return log_query_failure("CustomersDot returned no sessions connection", GET_SESSIONS_QUERY, response,
            reason: :malformed_response)
        end

        {
          success: true,
          sessions: Array(connection[:nodes]),
          page_info: connection[:pageInfo],
          # CustomersDot's sync watermark: a lag over about 30 minutes means their job is behind.
          synced_at: usage[:sessionsSyncedAt]
        }
      end

      # One page of root namespaces with changed sessions. Not memoized: the caller walks
      # successive pages. Every failure raises, as in get_sessions.
      def get_session_namespaces(updated_after:, first: SESSION_NAMESPACES_PAGE_SIZE, after: nil)
        response = execute_cdot_graphql(
          query: GET_SESSION_NAMESPACES_QUERY,
          variables: {
            updatedAfter: updated_after.getutc.iso8601(6),
            first: first,
            after: after.presence
          }.compact,
          read_timeout: CLICKHOUSE_QUERY_READ_TIMEOUT
        )

        reason = query_failure_reason(response, fields: SESSION_NAMESPACES_QUERY_FIELDS,
          unavailable_message: SESSION_NAMESPACES_UNAVAILABLE_MESSAGE)

        if reason
          return log_query_failure("CustomersDot sessionNamespaces query failed: #{reason}",
            GET_SESSION_NAMESPACES_QUERY, response, reason: reason)
        end

        connection = response.dig(:data, :sessionNamespaces)
        if connection.nil?
          return log_query_failure("CustomersDot returned no sessionNamespaces connection",
            GET_SESSION_NAMESPACES_QUERY, response, reason: :malformed_response)
        end

        { success: true, namespaces: Array(connection[:nodes]), page_info: connection[:pageInfo] }
      end

      def get_monthly_waiver
        response = execute_graphql_query(query: GET_MONTHLY_WAIVER_QUERY)

        if unsuccessful_response?(response)
          error(GET_MONTHLY_WAIVER_QUERY, response)
        else
          {
            success: true,
            monthlyWaiver: response.dig(:data, :subscription, :gitlabCreditsUsage, :monthlyWaiver)
          }
        end
      end

      def get_monthly_commitment
        response = execute_graphql_query(query: GET_MONTHLY_COMMITMENT_QUERY)

        if unsuccessful_response?(response)
          error(GET_MONTHLY_COMMITMENT_QUERY, response)
        else
          {
            success: true,
            monthlyCommitment: response.dig(:data, :subscription, :gitlabCreditsUsage, :monthlyCommitment)
          }
        end
      end
      strong_memoize_attr :get_monthly_commitment

      def get_overage
        response = execute_graphql_query(query: GET_OVERAGE_QUERY)

        if unsuccessful_response?(response)
          error(GET_OVERAGE_QUERY, response)
        else
          {
            success: true,
            overage: response.dig(:data, :subscription, :gitlabCreditsUsage, :overage)
          }
        end
      end
      strong_memoize_attr :get_overage

      def get_paid_tier_trial
        response = execute_graphql_query(query: GET_PAID_TIER_TRIAL_QUERY)

        if unsuccessful_response?(response)
          error(GET_PAID_TIER_TRIAL_QUERY, response)
        else
          {
            success: true,
            paidTierTrial: response.dig(:data, :subscription, :gitlabCreditsUsage, :paidTierTrial)
          }
        end
      end
      strong_memoize_attr :get_paid_tier_trial

      def get_products
        response = execute_graphql_query(query: GET_PRODUCTS_QUERY)

        if unsuccessful_response?(response)
          error(GET_PRODUCTS_QUERY, response)
        else
          {
            success: true,
            products: response.dig(:data, :subscription, :gitlabCreditsUsage, :products)
          }
        end
      end
      strong_memoize_attr :get_products

      def get_events_for_user_id(user_id, args)
        strong_memoize_with(:get_events_for_user_id, user_id, args) do
          variables = {
            userIds: [user_id],
            flowTypes: args[:flow_types],
            first: args[:first],
            last: args[:last],
            before: args[:before],
            after: args[:after]
          }.compact

          query = args[:include_non_billable] ? GET_USER_EVENTS_WITH_NON_BILLABLE_QUERY : GET_USER_EVENTS_QUERY

          # CustomersDot bounds these ClickHouse reads at 20s, so the default read timeout would
          # fire first and surface as Net::ReadTimeout instead of a CustomersDot error.
          response = execute_graphql_query(
            query: query, extra_variables: variables, read_timeout: CLICKHOUSE_QUERY_READ_TIMEOUT
          )

          if unsuccessful_response?(response)
            error(query, response)
          else
            user_events = response.dig(:data, :subscription, :gitlabCreditsUsage, :usersUsage, :users)
              .to_a.first&.fetch(:events)
            {
              success: true,
              userEvents: user_events
            }
          end
        end
      end

      def get_used_flow_types_for_user_id(user_id, include_non_billable: false)
        strong_memoize_with(:get_used_flow_types_for_user_id, user_id, include_non_billable) do
          variables = { userIds: [user_id] }
          query = include_non_billable ? GET_USED_FLOW_TYPES_WITH_NON_BILLABLE_QUERY : GET_USED_FLOW_TYPES_QUERY

          response = execute_graphql_query(
            query: query, extra_variables: variables, read_timeout: CLICKHOUSE_QUERY_READ_TIMEOUT
          )

          if unsuccessful_response?(response)
            error(query, response)
          else
            used_flow_types = response.dig(:data, :subscription, :gitlabCreditsUsage, :usersUsage, :users)
              .to_a.first&.fetch(:usedFlowTypes, nil)
            {
              success: true,
              usedFlowTypes: used_flow_types
            }
          end
        end
      end

      def get_daily_usage_for_user_id(user_id, flow_types: nil)
        strong_memoize_with(:get_daily_usage_for_user_id, user_id, flow_types) do
          response = execute_graphql_query(
            query: GET_USER_DAILY_USAGE_QUERY,
            extra_variables: { userIds: [user_id], flowTypes: flow_types.presence }.compact
          )

          if unsuccessful_response?(response)
            error(GET_USER_DAILY_USAGE_QUERY, response)
          else
            daily_usage = response.dig(:data, :subscription, :gitlabCreditsUsage, :usersUsage, :users)
              .to_a.first&.fetch(:dailyUsage, nil)
            {
              success: true,
              dailyUsage: daily_usage
            }
          end
        end
      end

      # Its own request rather than a field on get_daily_usage_for_user_id: CustomersDot
      # answers a ClickHouse failure here with an error, which would otherwise fail the
      # billable series too.
      def get_non_billable_usage_for_user_id(user_id, flow_types: nil)
        strong_memoize_with(:get_non_billable_usage_for_user_id, user_id, flow_types) do
          response = execute_graphql_query(
            query: GET_USER_NON_BILLABLE_USAGE_QUERY,
            extra_variables: { userIds: [user_id], flowTypes: flow_types.presence }.compact,
            read_timeout: CLICKHOUSE_QUERY_READ_TIMEOUT
          )

          if non_billable_usage_unavailable_error?(response)
            Gitlab::AppLogger.warn(
              Labkit::Fields::CLASS_NAME => self.class.name,
              Labkit::Fields::LOG_MESSAGE => "CustomersDot could not read nonBillableUsage for user"
            )

            { success: false, nonBillableUsage: nil }
          elsif unsuccessful_response?(response)
            error(GET_USER_NON_BILLABLE_USAGE_QUERY, response)
          else
            non_billable_usage = response.dig(:data, :subscription, :gitlabCreditsUsage, :usersUsage, :users)
              .to_a.first&.fetch(:nonBillableUsage, nil)
            {
              success: true,
              nonBillableUsage: non_billable_usage
            }
          end
        end
      end

      def get_usage_for_user_ids(user_ids, flow_types: nil)
        strong_memoize_with(:get_usage_for_user_ids, user_ids, flow_types) do
          variables = { userIds: user_ids, flowTypes: flow_types.presence }
          response = execute_graphql_query(query: GET_USERS_USAGE_QUERY, extra_variables: variables)

          if unsuccessful_response?(response)
            error(GET_USERS_USAGE_QUERY, response)
          else
            {
              success: true,
              usersUsage: response.dig(:data, :subscription, :gitlabCreditsUsage, :usersUsage, :users)
            }
          end
        end
      end

      def get_consumers(args)
        strong_memoize_with(:get_consumers, args) do
          variables = {
            sort: args[:sort]&.upcase,
            first: args[:first],
            last: args[:last],
            before: args[:before],
            after: args[:after],
            flowTypes: args[:flow_types].presence
          }

          query = GET_CONSUMERS_QUERY
          response = execute_graphql_query(query: query, extra_variables: variables)

          if complexity_error?(response)
            log_warning('CustomersDot rejected the consumers query for complexity, retrying without the breakdown',
              response)

            query = GET_CONSUMERS_WITHOUT_BREAKDOWN_QUERY
            response = execute_graphql_query(query: query, extra_variables: variables)
          end

          if unsuccessful_response?(response)
            error(query, response)
          else
            {
              success: true,
              consumers: response.dig(:data, :subscription, :gitlabCreditsUsage, :usersUsage, :consumers)
            }
          end
        end
      end

      def get_users_usage_stats(flow_types: nil)
        strong_memoize_with(:get_users_usage_stats, flow_types) do
          response = execute_graphql_query(
            query: GET_USERS_USAGE_STATS_QUERY,
            extra_variables: { flowTypes: flow_types.presence }.compact
          )

          if unsuccessful_response?(response)
            error(GET_USERS_USAGE_STATS_QUERY, response)
          else
            {
              success: true,
              usersUsage: response.dig(:data, :subscription, :gitlabCreditsUsage, :usersUsage)
            }
          end
        end
      end

      def get_trial_usage
        response = execute_graphql_query(query: GET_TRIAL_USAGE_QUERY)

        if unsuccessful_response?(response)
          error(GET_TRIAL_USAGE_QUERY, response)
        else
          {
            success: true,
            trialUsage: response.dig(:data, :trialUsage)
          }
        end
      end
      strong_memoize_attr :get_trial_usage

      def get_trial_usage_for_user_ids(user_ids)
        strong_memoize_with(:get_trial_usage_for_user_ids, user_ids) do
          response = execute_graphql_query(query: GET_TRIAL_USAGE_FOR_USER_IDS_QUERY,
            extra_variables: { userIds: user_ids })

          if unsuccessful_response?(response)
            error(GET_TRIAL_USAGE_FOR_USER_IDS_QUERY, response)
          else
            {
              success: true,
              usersUsage: response.dig(:data, :trialUsage, :usersUsage, :users)
            }
          end
        end
      end

      def get_budget_caps(entity_ids: nil, args: {})
        strong_memoize_with(:get_budget_caps, entity_ids, args) do
          variables = {
            instanceId: Gitlab::GlobalAnonymousId.instance_id,
            namespaceId: namespace_id,
            licenseKey: license_key,
            entityIds: entity_ids,
            first: args[:first],
            last: args[:last],
            before: args[:before],
            after: args[:after]
          }.compact

          response = execute_cdot_graphql(
            query: GET_BUDGET_CAPS_QUERY,
            variables: variables
          )

          if unsuccessful_response?(response)
            error(GET_BUDGET_CAPS_QUERY, response)
          else
            {
              success: true,
              budgetControls: response.dig(
                :data, :subscription, :budgetControls
              )
            }
          end
        end
      end

      def get_blocked_statuses(entity_ids)
        strong_memoize_with(:get_blocked_statuses, entity_ids) do
          response = execute_graphql_query(
            query: GET_BLOCKED_STATUSES_QUERY,
            extra_variables: { entityIds: entity_ids }
          )

          if unsuccessful_response?(response)
            error(GET_BLOCKED_STATUSES_QUERY, response)
          else
            {
              success: true,
              blockedStatuses: response.dig(
                :data, :subscription, :gitlabCreditsUsage, :blockedStatuses, :nodes
              )
            }
          end
        end
      end

      def upsert_user_budget_cap_overrides(overrides:)
        input = build_mutation_input(
          overrides: overrides,
          include_instance_id: true
        )

        execute_cdot_mutation(
          query: UPSERT_USER_BUDGET_CAPS_MUTATION,
          input: input,
          result_path: [:upsertUserBudgetCapsBulk],
          result_key: :userBudgetCapOverrides
        )
      end

      def upsert_flat_user_cap(flat_user_cap:, flat_user_cap_enabled:)
        input = build_mutation_input(
          flatUserCap: flat_user_cap,
          flatUserCapEnabled: flat_user_cap_enabled
        )

        execute_cdot_mutation(
          query: UPSERT_FLAT_USER_CAP_MUTATION,
          input: input,
          result_path: [:upsertBudgetCapSubscription],
          result_key: :subscriptionBudgetCap
        )
      end

      attr_reader :start_date, :end_date

      private

      attr_reader :namespace_id, :license_key

      def execute_graphql_query(query:, extra_variables: {}, read_timeout: nil)
        variables = {
          instanceId: Gitlab::GlobalAnonymousId.instance_id,
          namespaceId: namespace_id,
          licenseKey: license_key,
          startDate: start_date,
          endDate: end_date
        }.compact.merge(extra_variables)

        execute_cdot_graphql(query: query, variables: variables, read_timeout: read_timeout)
      end

      def build_mutation_input(include_instance_id: false, **fields)
        input = fields.dup

        unless license_key
          input[:namespaceId] = namespace_id
          return input
        end

        input[:licenseKey] = license_key
        input[:uniqueInstanceId] = Gitlab::GlobalAnonymousId.instance_id if include_instance_id

        input
      end

      def execute_cdot_mutation(query:, input:, result_path:, result_key:)
        response = execute_cdot_graphql(
          query: query,
          variables: { input: input }
        )

        return error(query, response) if unsuccessful_response?(response)

        mutation_data = response.dig(:data, *result_path)

        return error(query, response) if mutation_data.nil?
        return { success: false, errors: mutation_data[:errors] } if mutation_data[:errors].present?

        { success: true, result_key => mutation_data[result_key] }
      end

      def execute_cdot_graphql(query:, variables:, read_timeout: nil)
        headers = license_key ? json_headers : admin_headers
        headers['x-gitlab-namespace-id'] = namespace_id.to_s if namespace_id

        http_post_graphql(query: query, variables: variables, headers: headers, read_timeout: read_timeout)
      end

      def http_post_graphql(query:, variables:, headers:, read_timeout: nil)
        options = { headers: headers, body: { query: query, variables: variables }.to_json }
        options[:read_timeout] = read_timeout if read_timeout

        http_response = ::Gitlab::HTTP.post(::Gitlab::Routing.url_helpers.subscription_portal_graphql_url, **options)

        if http_response.response.is_a?(Net::HTTPSuccess)
          http_response.parsed_response.deep_symbolize_keys
        else
          {
            data: { errors: http_response.response.message },
            http_status: http_response.response.code.to_i,
            retry_after: retry_after_seconds(http_response.response)
          }.compact
        end
      end

      def unsuccessful_response?(response)
        return if response.dig(:data, :errors).blank? && response[:errors].blank?

        true
      end

      def non_billable_usage_unavailable_error?(response)
        Array(response[:errors]).any? { |error| error.dig(:extensions, :code) == NON_BILLABLE_USAGE_UNAVAILABLE_CODE }
      end

      # Error messages only, never response data, so an upstream value cannot look like
      # a failure. Both locations are read: top-level GraphQL errors and the data.errors
      # string http_post_graphql synthesises for non-2xx.
      def graphql_errors(response)
        [response[:errors], response.dig(:data, :errors)].flatten.compact
      end

      def graphql_error_messages(response)
        graphql_errors(response).map { |entry| entry.is_a?(Hash) ? entry[:message] : entry }.join("\n")
      end

      def kill_switch_error?(response)
        graphql_errors(response).any? do |entry|
          entry.is_a?(Hash) && entry.dig(:extensions, :code) == KILL_SWITCH_ERROR_CODE
        end
      end

      # graphql-ruby reports this as a top-level message with no extensions code:
      # "Query has complexity of 210, which exceeds max complexity of 200".
      def complexity_error?(response)
        graphql_error_messages(response).include?('exceeds max complexity')
      end

      # Named only so the log line can say which failure it was; every branch raises.
      # Field and message checks are scoped to this query, so an unrelated error is not ours.
      def query_failure_reason(response, fields:, unavailable_message:)
        messages = graphql_error_messages(response)

        if fields.any? { |field| messages.include?("Field '#{field}' doesn't exist") }
          :undefined_field
        elsif rate_limited?(response)
          :rate_limited
        elsif server_error?(response)
          :server_error
        elsif kill_switch_error?(response)
          :disabled
        elsif messages.include?(unavailable_message)
          :unavailable
        elsif unsuccessful_response?(response)
          :error
        end
      end

      # Logs a query failure and raises through error(), so callers can `return` it in one line.
      def log_query_failure(message, query, response, reason: nil)
        log_warning(message, response)

        error(query, response, reason: reason)
      end

      def log_warning(message, response)
        Gitlab::AppLogger.warn(
          Labkit::Fields::CLASS_NAME => self.class.name,
          Labkit::Fields::LOG_MESSAGE => message,
          Labkit::Fields::HTTP_STATUS_CODE => response[:http_status]
        )
      end

      def server_error?(response)
        status = response[:http_status].to_i

        status >= 500 || status == 429
      end

      def rate_limited?(response)
        response[:http_status].to_i == 429
      end

      # Whole seconds a 429 asks us to wait: an integer, or an HTTP-date. Anything else, or a
      # time already past, counts as no header.
      def retry_after_seconds(net_response)
        value = net_response['Retry-After'].to_s.strip
        return if value.empty?

        seconds = Integer(value, 10, exception: false) || (Time.httpdate(value) - Time.current).ceil
        seconds if seconds > 0
      rescue ArgumentError
        nil
      end

      def error(query, response, reason: nil)
        Gitlab::ErrorTracking.track_and_raise_exception(
          ResponseError.new("Received an error from CustomerDot", reason: reason, retry_after: response[:retry_after]),
          query: query,
          response: response
        )
      end

      def default_headers
        {
          "User-Agent" => "GitLab/#{Gitlab::VERSION}"
        }
      end

      def json_headers
        default_headers.merge(
          {
            'Accept' => 'application/json',
            'Content-Type' => 'application/json'
          }
        )
      end

      def admin_headers
        json_headers.merge(
          {
            'X-Admin-Email' => Gitlab::SubscriptionPortal::SUBSCRIPTION_PORTAL_ADMIN_EMAIL,
            'X-Admin-Token' => Gitlab::SubscriptionPortal::SUBSCRIPTION_PORTAL_ADMIN_TOKEN
          }
        )
      end
    end
  end
end
