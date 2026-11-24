# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module CreateMissingExternalLinksForVulnerabilities
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        LINK_TYPE = 1
        EXTERNAL_TYPE = 1
        MAX_RETRIES = 3
        DELAY = 2.seconds

        prepended do
          operation_name :create_missing_external_issue_links_for_vulnerabilities
          feature_category :vulnerability_management
          scope_to ->(relation) { relation.where('has_vulnerabilities IS TRUE') }
        end

        class Project < ::ApplicationRecord
          self.table_name = 'projects'
        end

        class Vulnerability < ::SecApplicationRecord
          self.table_name = 'vulnerabilities'
        end

        class User < ::ApplicationRecord
          self.table_name = "users"
        end

        class ExternalIssueLink < ::SecApplicationRecord
          self.table_name = 'vulnerability_external_issue_links'
        end

        class Integration < ::ApplicationRecord
          self.table_name = 'integrations'
        end

        class JiraIntegration < Integration
          has_one :jira_tracker_data, foreign_key: :integration_id, class_name: 'JiraTrackerData'

          AUTH_TYPE_PAT = 1

          def options
            url = URI.parse(client_url)

            options = {
              site: URI.join(url, '/').to_s.chomp('/'), # Find the root URL
              context_path: (url.path.presence || '/').delete_suffix('/'),
              auth_type: :basic,
              use_ssl: url.scheme == 'https'
            }

            if personal_access_token_authorization?
              options[:default_headers] = { 'Authorization' => "Bearer #{jira_tracker_data.password}" }
            else
              options[:username] = jira_tracker_data.username&.strip
              options[:password] = jira_tracker_data.password
              options[:use_cookies] = true
              options[:additional_cookies] = ['OBBasicAuth=fromDialog']
            end

            options
          end

          def client(additional_options = {})
            ::JIRA::Client.new(options.merge(additional_options)).tap do |client|
              # Replaces JIRA default http client with our implementation
              client.request_client = ::Gitlab::Jira::HttpClient.new(client.options)
            end
          end

          def client_url
            jira_tracker_data.api_url.presence || jira_tracker_data.url
          end

          def personal_access_token_authorization?
            jira_tracker_data.jira_auth_type == AUTH_TYPE_PAT
          end

          def project_keys
            jira_tracker_data.project_keys
          end

          def valid?
            return false if jira_tracker_data.nil?

            test_integration
          end

          def test_integration
            server_info.present? && client_info.present?
          end

          def client_info
            client_url.present? ? jira_request { client.User.myself.attrs } : nil
          end

          def server_info
            client_url.present? ? jira_request { client.ServerInfo.all.attrs } : nil
          end

          def jira_request
            yield
          rescue StandardError => _
            nil
          end
        end

        class JiraTrackerData < ::ApplicationRecord
          self.table_name = 'jira_tracker_data'

          include ::Integrations::BaseDataFields

          attr_encrypted :url, encryption_options
          attr_encrypted :api_url, encryption_options
          attr_encrypted :username, encryption_options
          attr_encrypted :password, encryption_options
        end

        class JiraIssuesFinder
          # This is mostly copy pasted code tracing the code flow from
          # Projects::Integrations::Jira::IssuesFinder#execute method
          def initialize(jira_integration)
            @jira_integration = jira_integration
            @client = @jira_integration.client
            @project_keys = @jira_integration.project_keys
          end

          def execute(page, per_page)
            jql = build_jql
            start_at = (page - 1) * per_page
            url = "#{context_path}/rest/api/2/search?jql=#{CGI.escape(jql)}&startAt=#{start_at}&" \
              "maxResults=#{per_page}&fields=description,project"
            request(url)
          end

          private

          def request(url)
            response = request_with_retry(url)

            return ServiceResponse.success(payload: empty_payload) if response.blank? || response["issues"].blank?

            ServiceResponse.success(payload: {
              issues: map_issues(response["issues"]),
              is_last: last?(response)
            })
          end

          def request_with_retry(url)
            retries = 0

            loop do
              return @client.get(url)
            rescue JIRA::HTTPError => _
              retries += 1

              raise if retries >= MAX_RETRIES

              sleep DELAY
              next
            end
          end

          def build_jql
            [
              jql_filters,
              order_by
            ].compact_blank.join(' ')
          end

          def jql_filters
            [
              by_project,
              by_description
            ].compact.join(' AND ')
          end

          def by_project
            return if @project_keys.blank?

            quoted_keys = @project_keys.map { |key| %("#{escape_quotes(key.to_s)}") }.join(',')

            %(project in \(#{quoted_keys}\))
          end

          def by_description
            %(description ~ "Issue created from vulnerability")
          end

          def order_by
            %(order by created DESC)
          end

          def map_issues(issues)
            issues.map { |v| ::JIRA::Resource::Issue.build(@client, v) }
          end

          def empty_payload
            { issues: [], is_last: true }
          end

          def last?(response)
            response["total"].to_i <= response["startAt"].to_i + response["issues"].size
          end

          def context_path
            @client.options[:context_path].to_s
          end

          def escape_quotes(param)
            param.gsub('\\', '\\\\\\').gsub('"', '\\"')
          end
        end

        override :perform

        def perform
          each_sub_batch do |sub_batch|
            project_ids = sub_batch.pluck(:project_id)
            integrations = JiraIntegration.where(project_id: project_ids, type_new: 'Integrations::Jira')
            valid_integrations = integrations.select(&:valid?)

            valid_integrations.each do |integration|
              page = 1
              per_page = 100
              jira_issues_finder = JiraIssuesFinder.new(integration)
              project = Project.find(integration.project_id)
              loop do
                response = jira_issues_finder.execute(page, per_page)
                response.payload[:issues].each do |jira_issue|
                  create_missing_external_issue_links(jira_issue, project)
                end
                page += 1
                break if response.payload[:is_last]
              end
            end
          end
        end

        private

        def create_missing_external_issue_links(jira_issue, project)
          # Check if the jira issue was created from a vulnerability (based on the description)
          # and extract the vulnerability ID from description
          issue_description = jira_issue.fields["description"]
          return unless issue_description&.include?('Issue created from vulnerability')

          vulnerability_id = extract_vulnerability_id(issue_description)
          return unless vulnerability_id

          vulnerability = Vulnerability.find_by(id: vulnerability_id, project_id: project.id)
          return unless vulnerability

          return unless ExternalIssueLink.find_by(vulnerability_id: vulnerability.id, external_type: EXTERNAL_TYPE).nil?

          # There is a also a service to create external issue links at
          # VulnerabilityExternalIssueLinks::CreateService
          # But it also creates jira issue along with vuilnerability_external_issue_link, so can't use that
          ExternalIssueLink.create(
            author_id: project.creator_id,
            vulnerability_id: vulnerability_id,
            link_type: LINK_TYPE,
            external_type: EXTERNAL_TYPE,
            external_project_key: jira_issue.fields.dig("project", "key"),
            external_issue_key: jira_issue.id
          )
        end

        def extract_vulnerability_id(string)
          match = string.match(%r{/-/security/vulnerabilities/(\d+)})
          match ? match[1].to_i : nil
        end
      end
    end
  end
end
