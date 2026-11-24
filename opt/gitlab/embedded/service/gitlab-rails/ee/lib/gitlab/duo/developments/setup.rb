# frozen_string_literal: true

# rubocop:disable Gitlab/DocumentationLinks/HardcodedUrl -- Development purpose
module Gitlab
  module Duo
    module Developments
      class BaseStrategy
        def initialize(namespace, args)
          @namespace = namespace
          @args = args
        end

        def execute
          puts(banner)
          validate!
          seed_data

          group = ensure_group!

          run(group)
          ensure_foundational_flows_enabled!(group)
        end

        private

        def banner
          raise NotImplementedError
        end

        def validate!; end

        def run(group)
          raise NotImplementedError
        end

        def admin
          @admin ||= User.admins.first
        end

        def seed_data
          return if @namespace.blank?

          if Group.find_by_full_path(@namespace) && !::Gitlab::Utils.to_boolean(ENV['GITLAB_DUO_RESEED'])
            puts <<~TXT.strip
          ================================================================================
          ## GitLab Duo test group and project already seeded
          ## If you want to destroy and re-create them, you can re-run the seed task
          ## SEED_GITLAB_DUO=1 FILTER=gitlab_duo bundle exec rake db:seed_fu
          ## Or set GITLAB_DUO_RESEED=1 to force reseeding via this setup task
          ## See https://docs.gitlab.com/development/development_seed_files/#seed-project-and-group-resources-for-gitlab-duo
          ================================================================================
            TXT
          else
            # see ee/db/fixtures/development/95_gitlab_duo.rb
            puts "Seeding GitLab Duo data..."
            ENV['FILTER'] = 'gitlab_duo'
            ENV['SEED_GITLAB_DUO'] = '1'
            Rake::Task['db:seed_fu'].reenable
            Rake::Task['db:seed_fu'].invoke
          end
        end

        def ensure_group!
          Group.find_by_full_path(@namespace) || raise(<<~MSG)
            Could not find the '#{@namespace}' group after seeding.
            Make sure GitLab Duo test data seeded successfully (see the output above), or set
            GITLAB_DUO_RESEED=1 to force a fresh seed.
          MSG
        end

        def ensure_foundational_flows_enabled!(group)
          puts "Enabling all foundational flows...."

          flows = ::Ai::Catalog::FoundationalFlow.all

          ::Ai::Catalog::Flows::SeedFoundationalFlowsService.new.execute

          ::Ai::CascadeDuoSettingsService.new(
            {
              enabled_foundational_flows: flows.map(&:foundational_flow_reference)
            },
            current_user: admin
          ).cascade_for_group(group)
        end

        def create_add_on_purchases!(group: nil)
          ::GitlabSubscriptions::AddOnPurchase.by_namespace(group).delete_all

          create_add_on_purchase!(group, :duo_core, 'A-S0001', "Duo Core add-on added...")

          case @args[:add_on]
          when 'duo_core'
            # Core already created, nothing more needed
          when 'duo_pro'
            create_add_on_purchase!(group, :code_suggestions, 'C-12345', "Duo Pro add-on added...")
          when 'self_hosted_dap'
            create_add_on_purchase!(group, :self_hosted_dap, 'C-27391', "Self Hosted DAP add-on added...")
          else
            # Default to enterprise
            create_add_on_purchase!(group, :duo_enterprise, 'C-98766', "Duo Enterprise add-on added...")
          end
        end

        # rubocop: disable CodeReuse/ActiveRecord -- SystemDefined::AddOn is a fixed items model, not a real AR model
        def create_add_on_purchase!(group, add_on_name, purchase_xid, message)
          add_on = ::GitlabSubscriptions::SystemDefined::AddOn.find_by!(name: add_on_name.to_s)
          response = ::GitlabSubscriptions::AddOnPurchases::CreateService.new(group, add_on, {
            quantity: 100,
            started_on: Time.current,
            expires_on: 1.year.from_now,
            purchase_xid: purchase_xid
          }).execute

          raise response.message unless response.success?

          response.payload[:add_on_purchase].update!(users: [admin])
          puts message
        end
        # rubocop: enable CodeReuse/ActiveRecord
      end

      class SelfManagedStrategy < BaseStrategy
        private

        def banner
          <<~TXT.strip
          ================================================================================
          ## Running self-managed mode setup
          ## If you want to run .com mode, set GITLAB_SIMULATE_SAAS=1
          ## and re-run this script
          ## See https://docs.gitlab.com/ee/development/ee_features.html#simulate-a-saas-instance
          ## for more information.
          ================================================================================
          TXT
        end

        def validate!
          ensure_not_simulating_saas!
          ensure_ai_gateway_url!
        end

        def run(_group)
          configure_ai_gateway_url!
          create_add_on_purchases!
        end

        def ensure_not_simulating_saas!
          return unless ::Gitlab::Utils.to_boolean(ENV['GITLAB_SIMULATE_SAAS'])

          raise <<~MSG
            Make sure 'GITLAB_SIMULATE_SAAS' environment variable is false or not set.
            See https://docs.gitlab.com/ee/development/ee_features.html#simulate-a-saas-instance for more information.
          MSG
        end

        def ensure_ai_gateway_url!
          return if ai_gateway_url.present?

          raise <<~MSG
            Set the 'DEVELOPMENT_AI_GATEWAY_URL' or 'AI_GATEWAY_URL' environment variable to the local
            AI Gateway URL (e.g. http://localhost:5052) before running this setup.
          MSG
        end

        def configure_ai_gateway_url!
          puts "Configuring the local AI Gateway URL...."

          ::Gitlab::CurrentSettings.current_application_settings.update!(ai_gateway_url: ai_gateway_url)
        end

        def ai_gateway_url
          (ENV['DEVELOPMENT_AI_GATEWAY_URL'].presence || ENV['AI_GATEWAY_URL'].presence)&.chomp('/')
        end
      end

      class GitlabComStrategy < BaseStrategy
        private

        def banner
          <<~TXT.strip
          ================================================================================
          ## Running GitLab.com mode setup for group '#{@namespace}'
          ## If you want to run self-managed mode, set GITLAB_SIMULATE_SAAS=0
          ## and re-run this script
          ## See https://docs.gitlab.com/ee/development/ee_features.html#simulate-a-saas-instance
          ## for more information.
          ================================================================================
          TXT
        end

        def run(group)
          ensure_application_settings!
          ensure_group_subscription!(group)
          ensure_group_settings!(group)
          create_add_on_purchases!(group: group)
        end

        def ensure_application_settings!
          puts "Enabling application settings...."

          Gitlab::CurrentSettings.current_application_settings.update!(
            check_namespace_plan: true,
            allow_local_requests_from_web_hooks_and_services: true,
            instance_level_ai_beta_features_enabled: true,
            duo_features_enabled: true
          )
        end

        # rubocop:disable CodeReuse/ActiveRecord -- Development purpose
        def ensure_group_subscription!(group)
          puts "Activating an Ultimate license to the group...."

          plan = ::GitlabSubscriptions::SystemDefined::Plan.find_by(name: "ultimate")

          GitlabSubscription.find_or_create_by(namespace: group).tap do |subscription|
            subscription.update!(hosted_plan_name_uid: plan.plan_name_uid_before_type_cast, seats: 100)
          end
        end
        # rubocop:enable CodeReuse/ActiveRecord

        def ensure_group_settings!(group)
          puts "Enabling the group settings...."

          group = Group.find(group.id) # Hard Reload for refreshing the cache
          group.update!(
            experiment_features_enabled: true
          )

          group.namespace_settings.update!(
            duo_features_enabled: true,
            duo_core_features_enabled: true
          )
        end
      end

      class Setup
        attr_reader :args

        def initialize(args)
          @args = args
          @namespace = ENV['GITLAB_DUO_GROUP_PATH'] || 'gitlab-duo'
        end

        def execute
          setup_strategy = if ::Gitlab::Utils.to_boolean(ENV['GITLAB_SIMULATE_SAAS'])
                             GitlabComStrategy.new(@namespace, @args)
                           else
                             SelfManagedStrategy.new(@namespace, @args)
                           end

          ensure_dev_mode!
          ensure_feature_flags!
          ensure_license!
          setup_strategy.execute

          print_result
        end

        private

        # rubocop:disable Style/GuardClause -- Keep it explicit
        def ensure_dev_mode!
          unless ::Gitlab.dev_or_test_env?
            raise <<~MSG
              Setup can only be performed in development or test environment, however, the current environment is #{ENV['RAILS_ENV']}.
            MSG
          end
        end
        # rubocop:enable Style/GuardClause

        def ensure_feature_flags!
          puts "Enabling feature flags...."

          Gitlab::Duo::Developments::FeatureFlagEnabler.execute
          ::Feature.enable(:enable_hamilton_in_user_preferences)

          # forbid_composite_identities_to_run_pipelines is disabled by default.
          # We disable it here for development to allow testing.
          # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/215193
          # TODO: Discuss removing the related code and this feature flag entirely.
          ::Feature.disable(:forbid_composite_identities_to_run_pipelines)
        end

        def ensure_license!
          license = ::License.current
          raise 'No license found' unless license
        end

        def print_result
          puts <<~MSG
            ----------------------------------------
            Setup Complete!
            ----------------------------------------

            Visit "#{Gitlab.config.gitlab.protocol}://#{Gitlab.config.gitlab.host}:#{Gitlab.config.gitlab.port}/#{@namespace.presence}" for testing GitLab Duo features.

            For more development guidelines, see https://docs.gitlab.com/ee/development/ai_features/.
          MSG

          Group.find_by_full_path(@namespace)
        end
      end
    end
  end
end
# rubocop:enable Gitlab/DocumentationLinks/HardcodedUrl
