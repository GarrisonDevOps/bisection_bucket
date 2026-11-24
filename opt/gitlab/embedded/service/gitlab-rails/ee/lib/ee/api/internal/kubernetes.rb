# frozen_string_literal: true

module EE
  module API
    module Internal
      module Kubernetes
        extend ActiveSupport::Concern

        prepended do
          helpers do
            # @param [Clusters::Agent] agent
            # @param [Hash] config
            # @return [TrueClass]
            def update_configuration(agent:, config:)
              super

              if ::License.feature_available?(:remote_development)
                # NOTE: The other existing service called from the `internal/kubernetes/agent_configuration` API
                #       endpoint (::Clusters::Agents::RefreshAuthorizationService) does not use ServiceResponse, it just
                #       returns a boolean value. So we do the same from our CommonService (return the ServiceResponse,
                #       which is truthy) for consistency, even though the return value is ignored, and not even checked
                #       for errors. The `internal/kubernetes/agent_configuration` endpoint explicitly returns
                #       `no_content!` regardless of the return value, so it wouldn't matter what we returned anyway.
                #       We _don't_ want to change this behavior for now or return an exception in the case of failure,
                #       because that could potentially interfere with the existing behavior of the endpoint, which is
                #       to execute ::Clusters::Agents::RefreshAuthorizationService. So, it's safer to just silently
                #       fail to save the record, log an error, return a boolean for now.
                #
                #       Note that we have abstracted this logic to our domain-layer tier in `lib/remote_development`,
                #       and still attempt to return an appropriate ServiceResponse object, even though it is ignored,
                #       so that abstracts us somewhat from whatever we decide to do with this error handling
                #       at the Service layer.
                #
                #       We originally had planned to try to fix this (see
                #       https://gitlab.com/groups/gitlab-org/-/epics/10461 and
                #       https://gitlab.com/gitlab-org/gitlab/-/issues/402718, now both closed).
                #
                #       However, our current thinking is to instead migrate all settings (except `enabled`) out of the
                #       AgentConfig and into the UI. And perhaps eventually more `enabled` too. After we do that, we
                #       will not need this update service anymore, so fixing this error handling is no longer a
                #       priority.
                domain_main_class_args = {
                  agent: agent,
                  config: config
                }

                ::RemoteDevelopment::CommonService.execute(
                  domain_main_class: ::RemoteDevelopment::AgentConfigOperations::Main,
                  domain_main_class_args: domain_main_class_args
                )
              end

              # TODO: https://gitlab.com/groups/gitlab-org/-/epics/12225 - Add at least some logging here.
              true
            end
          end

          namespace 'internal' do
            namespace 'kubernetes/receptive_agents' do
              desc 'GET receptive agents' do
                detail 'Retrieve agents to maintain a connection with'
              end
              route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
              get '/', feature_category: :deployment_management, urgency: :low do
                not_found! unless ::License.feature_available?(:cluster_receptive_agents)

                present ::Clusters::Agents::UrlConfiguration.active,
                  with: ::API::Entities::Clusters::ReceptiveAgent,
                  root: :agents
              end
            end

            namespace 'kubernetes' do
              before { check_agent_token }

              namespace 'modules/remote_development' do
                before  { set_agent_on_context(agent: agent) }

                desc 'GET remote development prerequisites request' do
                  detail 'Remote development prerequisites request'
                end

                route_setting :authentication, cluster_agent_token_allowed: true
                route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                get '/prerequisites', urgency: :low, feature_category: :workspaces do
                  unless ::License.feature_available?(:remote_development)
                    forbidden!('"remote_development" licensed feature is not available')
                  end

                  unless agent.unversioned_latest_workspaces_agent_config
                    not_acceptable!(
                      'The remote development workspaces config for the agent is invalid. ' \
                        'Please see https://docs.gitlab.com/user/workspace/settings/#configuration-reference'
                    )
                  end

                  domain_main_class_args = {
                    agent: agent
                  }

                  response = ::RemoteDevelopment::CommonService.execute(
                    domain_main_class: ::RemoteDevelopment::AgentPrerequisitesOperations::Main,
                    domain_main_class_args: domain_main_class_args
                  )

                  if response.success?
                    response.payload
                  else
                    render_api_error!({ error: response.message }, response.http_status)
                  end
                end

                desc 'POST remote development reconciliation request' do
                  detail 'Remote development reconciliation request'
                end

                route_setting :authentication, cluster_agent_token_allowed: true
                route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                post '/reconcile', urgency: :low, feature_category: :workspaces do
                  unless ::License.feature_available?(:remote_development)
                    forbidden!('"remote_development" licensed feature is not available')
                  end

                  domain_main_class_args = {
                    original_params: params,
                    agent: agent
                  }

                  response = ::RemoteDevelopment::CommonService.execute(
                    domain_main_class: ::RemoteDevelopment::WorkspaceOperations::Reconcile::Main,
                    domain_main_class_args: domain_main_class_args
                  )

                  if response.success?
                    response.payload
                  else
                    render_api_error!({ error: response.message }, response.http_status)
                  end
                end
              end

              namespace 'modules/starboard_vulnerability' do
                desc 'PUT starboard vulnerability' do
                  detail 'Idempotently creates a security vulnerability from starboard'
                end
                params do
                  requires :vulnerability, type: Hash,
                    desc: 'Vulnerability details matching the `vulnerability` object on the security report schema' do
                    requires :name, type: String, desc: 'Name of the security vulnerability'
                    requires :severity, type: String, desc: 'Severity level of the vulnerability',
                      coerce_with: ->(s) { s.downcase }
                    optional :confidence, type: String, desc: 'Confidence level of the vulnerability detection',
                      coerce_with: ->(c) { c.downcase }

                    requires :location, type: Hash, desc: 'Object that contains location information for the
                      vulnerability' do
                      requires :image, type: String, desc: 'Container image where the vulnerability was found'

                      requires :dependency, type: Hash, desc: 'Object that contains dependency information for the
                        vulnerable component' do
                        requires :package, type: Hash, desc: 'Object that contains package details of the vulnerable
                          dependency' do
                          requires :name, type: String, desc: 'Name of the vulnerable package'
                        end

                        optional :version, type: String, desc: 'Version of the vulnerable dependency'
                      end

                      requires :kubernetes_resource, type: Hash, desc: 'Object that contains Kubernetes resource
                        information where the vulnerability exists' do
                        requires :namespace, type: String, desc: 'Kubernetes namespace of the resource'
                        requires :name, type: String, desc: 'Name of the Kubernetes resource'
                        requires :kind, type: String, desc: 'Type of Kubernetes resource'
                        requires :container_name, type: String, desc: 'Name of the container within the
                          Kubernetes resource'
                        requires :agent_id, type: String, desc: 'ID of the agent that detected the vulnerability'
                      end

                      optional :operating_system, type: String, desc: 'Operating system where the vulnerability
                        was detected'
                    end

                    requires :identifiers, type: Array, desc: 'Array of vulnerability identifier objects' do
                      requires :type, type: String, desc: 'Type of vulnerability identifier'
                      requires :name, type: String, desc: 'Name of the vulnerability identifier'
                      optional :value, type: String, desc: 'Value of the vulnerability identifier'
                      optional :url, type: String, desc: 'URL reference for the vulnerability identifier'
                    end

                    optional :message, type: String, desc: 'Vulnerability message or summary'
                    optional :description, type: String, desc: 'Detailed description of the vulnerability'
                    optional :solution, type: String, desc: 'Recommended solution for the vulnerability'
                    optional :links, type: Array, desc: 'Array that contains reference links
                      related to the vulnerability'
                  end

                  requires :scanner, type: Hash,
                    desc: 'Scanner details matching the `.scan.scanner` field on the security report schema' do
                    requires :id, type: String, desc: 'ID of the scanner'
                    requires :name, type: String, desc: 'Name of the security scanner'
                    requires :vendor, type: Hash, desc: 'Object that contains vendor information for the scanner' do
                      requires :name, type: String, desc: 'Name of the scanner vendor'
                    end
                  end
                end

                route_setting :authentication, cluster_agent_token_allowed: true
                route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                put '/', feature_category: :container_scanning, urgency: :low do
                  not_found! if agent.project.nil?

                  result = ::Vulnerabilities::StarboardVulnerabilityCreateService.new(
                    agent,
                    params: params
                  ).execute

                  if result.success?
                    status result.http_status
                    { uuid: result.payload[:vulnerability].finding_uuid }
                  elsif result.reason == :tracked_context_busy
                    # The agent can retry; a 500 would make it look like a server fault.
                    conflict!(result.message)
                  else
                    render_api_error!(result.message, result.http_status)
                  end
                end

                desc 'POST scan_result' do
                  detail 'Resolves all active Cluster Image Scanning vulnerabilities with ' \
                    'finding UUIDs not present in the payload'
                end
                params do
                  requires :uuids, type: Array[String], desc: 'Finding UUIDs collected from a scan'
                end

                route_setting :authentication, cluster_agent_token_allowed: true
                route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                post "/scan_result", feature_category: :container_scanning, urgency: :low do
                  not_found! if agent.project.nil?

                  service = ::Vulnerabilities::StarboardVulnerabilityResolveService.new(agent, params[:uuids])
                  result = service.execute

                  status result.http_status
                end

                desc 'GET starboard policies_configuration' do
                  detail 'Retrieves policies_configuration for the project'
                end

                route_setting :authentication, cluster_agent_token_allowed: true
                route_setting :authorization, skip_granular_token_authorization: :kas_jwt_auth
                get '/policies_configuration', feature_category: :container_scanning, urgency: :low do
                  not_found! if agent.project.nil?

                  unless agent.project.licensed_feature_available?(:security_orchestration_policies)
                    render_api_error!('Payment Required', 402)
                  end

                  policies = ::Security::SecurityOrchestrationPolicies::OperationalVulnerabilitiesConfigurationService
                               .new(agent)
                               .execute

                  present :configurations, policies, with: ::API::Entities::SecurityPolicyConfiguration
                end
              end
            end
          end
        end
      end
    end
  end
end
