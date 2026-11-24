# frozen_string_literal: true

# Part of gitlab:ai_catalog:seed_external_agents Rake task for Self-managed
module Gitlab
  module Ai
    module Catalog
      module ThirdPartyFlows
        class Seeder
          PRODUCTION_AI_GATEWAY_URL = 'https://cloud.gitlab.com/ai'

          def self.run!
            new.run!
          end

          def initialize
            # rubocop:disable Gitlab/AvoidDefaultOrganization -- no other organization in context
            @organization = ::Organizations::Organization.default_organization
            # rubocop:enable Gitlab/AvoidDefaultOrganization
          end

          def agents
            [
              {
                name: 'Claude Agent by GitLab',
                description: "Claude Code Agent by GitLab. Uses GitLab-managed credentials.\n\n" \
                  "Learn more: #{external_agents_docs_url}",
                definition: <<~YAML
                injectGatewayToken: true
                image: node:22-slim
                commands:
                  - echo "Installing claude"
                  - npm install -g @anthropic-ai/claude-code
                  - echo "Installing glab"
                  - apt-get update -q && apt-get install -y curl wget gpg git && rm -rf /var/lib/apt/lists/*
                  - |
                    #{glab_install_command}
                  - #{glab_path_command}
                  - mkdir -p ~/.config/glab-cli
                  - |
                    cat > ~/.config/glab-cli/config.yml <<EOF
                    hosts:
                      $AI_FLOW_GITLAB_HOSTNAME:
                        token: $AI_FLOW_GITLAB_TOKEN
                        is_oauth2: "true"
                        client_id: "bypass"
                        oauth2_refresh_token: ""
                        oauth2_expiry_date: "01 Jan 50 00:00 UTC"
                        api_host: $AI_FLOW_GITLAB_HOSTNAME
                        user: ClaudeCode
                    check_update: "false"
                    git_protocol: https
                    EOF
                  - chmod 600 ~/.config/glab-cli/config.yml
                  - echo "Setting up git remote with authentication"
                  - git remote set-url origin https://gitlab-ci-token:$AI_FLOW_GITLAB_TOKEN@$AI_FLOW_GITLAB_HOSTNAME/$AI_FLOW_PROJECT_PATH.git
                  - export ANTHROPIC_AUTH_TOKEN=$AI_FLOW_AI_GATEWAY_TOKEN
                  - export ANTHROPIC_CUSTOM_HEADERS=$AI_FLOW_AI_GATEWAY_HEADERS
                  - export ANTHROPIC_BASE_URL="#{anthropic_base_url}"
                  - echo "Running claude"
                  - |
                    claude --allowedTools="Bash(glab:*),Bash(git:*)" --permission-mode acceptEdits --setting-sources '' --verbose --output-format stream-json -p "
                    You are an AI assistant helping with GitLab operations.

                    Context: $AI_FLOW_CONTEXT
                    Task: $AI_FLOW_INPUT
                    Event: $AI_FLOW_EVENT

                    Please execute the requested task using the available GitLab tools.
                    Be thorough in your analysis and provide clear explanations.

                    <important>
                    Use the glab CLI to access data from GitLab. The glab CLI has already been authenticated. You can run the corresponding commands.

                    When you complete your work create a new Git branch, if you aren't already working on a feature branch, with the format of 'feature/<short description of feature>' and check in/push code.

                    When you check in and push code, you will need to use the access token stored in GITLAB_TOKEN and the user ClaudeCode.
                    Lastly, after pushing the code, if a merge request doesn't already exist, create a new merge request for the branch and link it to the issue using:
                    glab mr create --title '<title>' --description '<desc>' --source-branch '<branch>'

                    If you are asked to summarize a merge request or issue, or asked to provide more information then please post back a note to the merge request / issue so that the user can see it.

                    $ADDITIONAL_INSTRUCTIONS
                    </important>
                    "
                variables:
                  - ADDITIONAL_INSTRUCTIONS
                YAML
              },
              {
                name: 'Codex Agent by GitLab',
                description: "Codex Agent by GitLab. Uses GitLab-managed credentials.\n\n" \
                  "Learn more: #{external_agents_docs_url}",
                definition: <<~YAML
                image: node:22-slim
                injectGatewayToken: true
                commands:
                  - echo "Installing codex"
                  - npm install --global @openai/codex
                  - echo "Installing glab"
                  - export OPENAI_API_KEY=$AI_FLOW_AI_GATEWAY_TOKEN
                  - apt-get update --quiet && apt-get install --yes curl wget gpg git && rm --recursive --force /var/lib/apt/lists/*
                  - |
                    #{glab_install_command}
                  - #{glab_path_command}
                  - mkdir -p ~/.config/glab-cli
                  - |
                    cat > ~/.config/glab-cli/config.yml <<EOF
                    hosts:
                      $AI_FLOW_GITLAB_HOSTNAME:
                        token: $AI_FLOW_GITLAB_TOKEN
                        is_oauth2: "true"
                        client_id: "bypass"
                        oauth2_refresh_token: ""
                        oauth2_expiry_date: "01 Jan 50 00:00 UTC"
                        api_host: $AI_FLOW_GITLAB_HOSTNAME
                        user: OpenAICodex
                    check_update: "false"
                    git_protocol: https
                    EOF
                  - chmod 600 ~/.config/glab-cli/config.yml
                  - echo "Setting up git remote with authentication"
                  - git remote set-url origin https://gitlab-ci-token:$AI_FLOW_GITLAB_TOKEN@$AI_FLOW_GITLAB_HOSTNAME/$AI_FLOW_PROJECT_PATH.git
                  - echo "Running Codex"
                  - |
                    # Parse AI_FLOW_AI_GATEWAY_HEADERS (newline-separated "Key: Value" pairs)
                    header_str="{"
                    first=true
                    while IFS= read -r line; do
                      # skip empty lines
                      [ -z "$line" ] && continue
                      key="${line%%:*}"
                      value="${line#*: }"
                      if [ "$first" = true ]; then
                        first=false
                      else
                        header_str+=", "
                      fi
                      header_str+="'$key' = '$value'"
                    done <<< "$AI_FLOW_AI_GATEWAY_HEADERS"
                    header_str+="}"

                    echo "Headers: $header_str"

                    codex exec \
                      --config 'model="gpt-5.3-codex"' \
                      --config 'model_provider="gitlab"' \
                      --config 'model_providers.gitlab.name="GitLab Managed Codex"' \
                      --config 'model_providers.gitlab.base_url="#{openai_base_url}"' \
                      --config 'model_providers.gitlab.env_key="OPENAI_API_KEY"' \
                      --config 'model_providers.gitlab.wire_api="responses"' \
                      --config "model_providers.gitlab.http_headers=${header_str}" \
                      --config shell_environment_policy.ignore_default_excludes=true \
                      --dangerously-bypass-approvals-and-sandbox "
                    You are an AI assistant helping with GitLab operations.

                    Context: $AI_FLOW_CONTEXT
                    Task: $AI_FLOW_INPUT
                    Event: $AI_FLOW_EVENT

                    Please execute the requested task using the available GitLab tools.
                    Be thorough in your analysis and provide clear explanations.

                    <important>
                    Use the glab CLI to access data from GitLab. The glab CLI has already been authenticated. You can run the corresponding commands.

                    When you complete your work create a new Git branch, if you aren't already working on a feature branch, with the format of 'feature/<short description of feature>' and check in/push code.

                    When you check in and push code, you will need to use the access token stored in GITLAB_TOKEN and the user OpenAICodex.
                    Lastly, after pushing the code, if a merge request doesn't already exist, create a new merge request for the branch and link it to the issue using:
                    glab mr create --title '<title>' --description '<desc>' --source-branch '<branch>'

                    If you are asked to summarize a merge request or issue, or asked to provide more information then please post back a note to the merge request / issue so that the user can see it.

                    $ADDITIONAL_INSTRUCTIONS
                    </important>
                    "
                variables:
                  - ADDITIONAL_INSTRUCTIONS
                YAML
              }
            ]
          end

          def run!
            if !Rails.env.development? && Gitlab::Saas.feature_available?(:ai_catalog)
              raise "Error: Cannot be run on production GitLab SaaS environments"
            end

            raise "Error: no organization found on instance" unless @organization
            # Error message hardcoded in frontend
            # https://gitlab.com/gitlab-org/gitlab/-/blob/d3d0f1f79c78b3db36285b3988dfa492ddd632f4/ee/app/assets/javascripts/ai/settings/constants.js#L33
            raise "Error: External agents already seeded" if already_seeded?

            unless Feature.enabled?(:ai_catalog_third_party_flows, :instance)
              raise "Error: ai_catalog_third_party_flows feature flag must be enabled"
            end

            puts "Seeding AI Catalog with external agents..."

            ::Ai::Catalog::Item.transaction do
              agents.each do |agent_config|
                seed_agent(agent_config)
              end
            end

            puts "Completed successfully!"
          end

          private

          def gateway_base_url
            return PRODUCTION_AI_GATEWAY_URL unless Rails.env.development?

            ::Gitlab::AiGateway.url
          end

          def anthropic_base_url
            "#{gateway_base_url}/v1/proxy/anthropic"
          end

          def openai_base_url
            "#{gateway_base_url}/v1/proxy/openai/v1"
          end

          # Embedded as a YAML block scalar because the command contains ": ",
          # which a plain scalar rejects.
          def glab_install_command
            ::Gitlab::DuoWorkflow::GlabSetup.install_command
          end

          def glab_path_command
            %(export PATH="#{::Gitlab::DuoWorkflow::GlabSetup::GLAB_BIN_DIR}:$PATH")
          end

          def external_agents_docs_url
            Rails.application.routes.url_helpers.help_page_url('user/duo_agent_platform/agents/external.md')
          end

          def already_seeded?
            ::Ai::Catalog::Item
              .in_organization(@organization)
              .for_project(nil)
              .not_deleted
              .public_only
              .with_item_type(::Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE)
              .for_verification_level(:gitlab_maintained)
              .exists?
          end

          def seed_agent(agent_config)
            item = ::Ai::Catalog::Item.new(
              organization: @organization,
              project: nil,
              name: agent_config[:name],
              description: agent_config[:description],
              item_type: ::Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE,
              verification_level: :gitlab_maintained,
              visibility: :public
            )

            build_version(item, agent_config)

            item.save!
            item.update!(latest_released_version: item.latest_version)
            item
          end

          def build_version(item, agent_config)
            yaml_definition = YAML.safe_load(
              agent_config[:definition], permitted_classes: [], aliases: false
            ).merge('yaml_definition' => agent_config[:definition])

            version_params = {
              schema_version: ::Ai::Catalog::ItemVersion::THIRD_PARTY_FLOW_SCHEMA_VERSION,
              version: ::Ai::Catalog::BaseService::DEFAULT_VERSION,
              definition: yaml_definition,
              release_date: Time.zone.now
            }

            item.build_new_version(version_params)
            item
          end
        end
      end
    end
  end
end
