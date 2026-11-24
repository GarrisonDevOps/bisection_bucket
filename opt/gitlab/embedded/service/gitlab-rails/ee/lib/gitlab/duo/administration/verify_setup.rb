# frozen_string_literal: true

module Gitlab
  module Duo
    module Administration
      class VerifySetup
        MAX_COLS = 120
        SEPARATOR = ("═" * MAX_COLS).freeze
        THIN_SEPARATOR = ("-" * MAX_COLS).freeze

        delegate :root_ancestor, to: :project

        def initialize(project_path)
          @project_path = project_path
          @project = ::Project.find_by_full_path(project_path)
        end

        def execute
          validate!
          print_header
          check_license
          check_instance_duo_settings
          check_duo_runners
          check_project
          return unless project

          check_namespace_duo_settings
          check_project_duo_settings
          check_foundational_flows
          check_duo_code_review
          print_footer
        end

        private

        attr_reader :project_path, :project

        def section(title)
          output
          output(SEPARATOR)
          output("  #{title}")
          output(SEPARATOR)
        end

        def ok(msg)
          print_wrapped("  ✔  ", msg)
        end

        def warn(msg)
          print_wrapped("  ⚠  ", msg)
        end

        def error(msg)
          print_wrapped("  ✗  ", msg)
        end

        def info(msg)
          print_wrapped("     ", msg)
        end

        def execution_docs_url
          Rails.application.routes.url_helpers.help_page_url('user/duo_agent_platform/flows/execution/_index.md')
        end

        # Wraps `msg` so lines stay within MAX_COLS, instead of the naive truncation `output`
        # applies as a last-resort safety net. Preserves `prefix` on the first line, an
        # equal-width indent on continuation lines, and any leading whitespace already present
        # in `msg` (used to visually nest sub-points under a preceding line).
        def print_wrapped(prefix, msg)
          text = msg.to_s
          sub_indent = text[/\A */]
          content = text[sub_indent.length..]
          indent = ' ' * prefix.length
          width = [MAX_COLS - prefix.length - sub_indent.length, 1].max

          wrap_lines(content, width).each_with_index do |line, index|
            line_prefix = index == 0 ? prefix : indent
            output("#{line_prefix}#{sub_indent}#{line}")
          end
        end

        def wrap_lines(text, width)
          return [text] if text.length <= width

          words = text.split(' ')
          return [''] if words.empty?

          words.each_with_object([]) do |word, lines|
            if lines.any? && (lines.last.length + 1 + word.length) <= width
              lines.last << ' ' << word
            else
              lines << word.dup
            end
          end
        end

        def warn_and_exit_if(condition, message)
          return unless condition

          warn(message)
          exit 1
        end

        def print_header
          output
          output(SEPARATOR)
          output("  GitLab Duo Code Review - Configuration debugger")
          output("  Project:   #{project_path}")
          output("  Generated: #{Time.current.iso8601}")
          output(SEPARATOR)
        end

        def print_footer
          output
          output(SEPARATOR)
          output("  Debug complete. Sanitize output before sharing with support.")
          output(SEPARATOR)
          output
        end

        # rubocop:disable CodeReuse/ActiveRecord -- Support debugging task, direct query needed
        def enabled_catalog_items
          @enabled_catalog_items ||= ::Ai::Catalog::Item
              .where(id: project.enabled_flow_catalog_item_ids)
              .pluck(:id, :foundational_flow_reference)
              .to_h
        end

        ## Returns a hash of { catalog_item_id => service_account_user } for the given item IDs.
        # Service accounts are always provisioned at the root-group level; project-level consumers
        # inherit theirs via parent_item_consumer. We check the project first and fall back to the
        # root namespace so the effective service account is always surfaced correctly.
        def service_accounts_by_catalog_item_id
          consumers = ::Ai::Catalog::ItemConsumer
            .includes(:service_account, parent_item_consumer: :service_account)
            .where(ai_catalog_item_id: enabled_catalog_items.keys)
            .where("project_id = ? OR group_id = ?", project.id, root_ancestor.id)

          # Project-level consumer always wins; group-level is the fallback when no project entry exists.
          consumers.each_with_object({}) do |consumer, result|
            catalog_item_id = consumer.ai_catalog_item_id
            service_account = consumer.active_service_account

            next unless service_account

            if consumer.project_id == project.id
              result[catalog_item_id] = service_account
            else
              result[catalog_item_id] ||= service_account
            end
          end
        end
        # rubocop:enable CodeReuse/ActiveRecord

        def validate!
          warn_and_exit_if(
            project_path.blank?,
            "Usage: bundle exec rake \"gitlab:support:duo_code_review_debug[PROJECT_PATH]\""
          )

          warn_and_exit_if(
            project.nil?,
            "Project \"#{project_path}\" does not exist. Check the path and try again."
          )
        end

        def check_license
          section("1. License")

          license = ::License.current

          unless license
            error("No active license found")
            info("This instance has no license. All EE features including Duo are unavailable.")
            return
          end

          ok("License found")
          info("Plan:       #{license.plan.upcase}")
          info("Licensee:   #{license.licensee_company || license.licensee.each_value.first}")
          info("Expires at: #{license.expires_at&.strftime('%Y-%m-%d') || 'never'}")
          info("Expired:    #{license.expired? ? 'YES ⚠' : 'no'}")
          info("Trial:      #{license.trial? ? 'yes' : 'no'}")

          output

          if ::License.ai_features_available?
            ok("AI features licensed (:ai_features / :ai_chat)")
          else
            error("AI features NOT licensed — Duo requires :ai_features or :ai_chat")
          end

          if ::License.duo_core_features_available?
            ok("Duo Core features licensed (:code_suggestions / :ai_chat)")
          else
            warn("Duo Core features NOT licensed (:code_suggestions / :ai_chat)")
          end
        end

        def check_instance_duo_settings
          section("2. Instance-level Duo Settings")

          duo_enabled = ::Gitlab::CurrentSettings.duo_features_enabled
          if duo_enabled
            ok("Duo features enabled at instance level (application_settings.duo_features_enabled = true)")
          else
            error("Duo features DISABLED at instance level (application_settings.duo_features_enabled = false)")
            info("All namespace/project Duo settings are irrelevant until this is enabled.")
          end
        end

        def check_duo_runners
          section("3. CI Runners with '#{::Ai::DuoWorkflows::Workflow::WORKLOAD_TAG}' tag")

          tag = ::Ai::DuoWorkflows::Workflow::WORKLOAD_TAG

          instance_count = ::Ci::Runner.instance_type.with_tag(tag).count
          group_count    = ::Ci::Runner.group_type.with_tag(tag).count
          project_count  = ::Ci::Runner.project_type.with_tag(tag).count

          eligible_count = instance_count + group_count

          info("Instance runners:       #{instance_count}")
          info("Group runners:          #{group_count}")
          info("Project runners:        #{project_count}")

          output

          if eligible_count > 0
            ok("#{eligible_count} eligible runner(s) found (instance or group scope)")

            if project_count > 0
              warn("#{project_count} project-scoped runner(s) also have this tag — they cannot execute Duo flows")
              info("Remove the '#{tag}' tag from project runners to avoid misconfiguration.")
            end
          else
            error("No eligible runners found with the '#{tag}' tag")
            info("Duo Agent Platform requires at least one instance-wide or group runner")
            info("with the '#{tag}' tag to execute foundational flows.")
            info("Docs: #{execution_docs_url}")
          end
        end

        def check_project
          section("4. Project: #{project_path}")

          if project
            ok("Project found: \"#{project.name}\" (ID: #{project.id})")
            info("Full path:  #{project.full_path}")
            info("Namespace:  #{project.namespace.full_path} (ID: #{project.namespace.id})")
            info("Root group: #{root_ancestor.full_path} (ID: #{root_ancestor.id})")
            info("Visibility: #{project.visibility}")
            info("Archived:   #{project.archived? ? 'yes ⚠' : 'no'}")
          else
            error("Project not found for path: \"#{project_path}\"")
            info("Usage: bundle exec rake \"gitlab:support:duo_code_review_debug[GROUP/PROJECT]\"")
            info("Example paths: my-group/my-project, my-group/sub-group/my-project")
          end
        end

        def check_namespace_duo_settings
          section("5. Duo Settings for Namespace: #{project.namespace.full_path}")

          ns = project.namespace
          ns_setting = ns.namespace_settings

          if ns_setting.nil?
            warn("No namespace_settings record found for namespace #{ns.full_path}")
            return
          end

          duo_enabled = ns.duo_features_enabled
          locked = ns_setting.duo_features_enabled_locked?(include_self: true)

          if duo_enabled
            ok("Duo features enabled for namespace")
          else
            error("Duo features DISABLED for namespace — project inherits this")
          end

          info("duo_features_enabled (stored): #{ns_setting.duo_features_enabled.inspect}")
          info("Inherited/effective value:     #{duo_enabled.inspect}")
          info("Locked by ancestor:            #{locked ? 'yes (cannot be overridden by sub-groups)' : 'no'}")
        end

        def check_project_duo_settings
          section("6. Duo Settings for Project: #{project.full_path}")

          project_setting = project.project_setting

          if project_setting.nil?
            warn("No project_setting record found for this project")
            return
          end

          duo_enabled = project.duo_features_enabled

          if duo_enabled
            ok("Duo features enabled for project (effective value)")
          else
            error("Duo features DISABLED for project (effective value)")
          end

          info("duo_features_enabled (stored in project_settings): #{project_setting.duo_features_enabled.inspect}")
          info("Effective value (cascaded from namespace if nil):  #{duo_enabled.inspect}")
        end

        def check_foundational_flows
          section("7. Foundational Flows for Project: #{project.full_path}")

          foundational_enabled = project.duo_foundational_flows_enabled

          if foundational_enabled
            ok("Foundational flows enabled (duo_foundational_flows_enabled = true)")
          else
            error("Foundational flows DISABLED (duo_foundational_flows_enabled = false)")
            info("Duo Code Review (DAP mode) requires foundational flows to be enabled.")
          end

          if enabled_catalog_items.empty?
            warn("No foundational flows are enabled for this project or its namespace ancestors")
          else
            ok("Enabled foundational flows (#{enabled_catalog_items.length}):")

            enabled_catalog_items.each do |catalog_item_id, flow_reference|
              sa = service_accounts_by_catalog_item_id[catalog_item_id]
              info("  • #{flow_reference} (catalog item ID: #{catalog_item_id})")

              if sa
                info("       Service account: #{sa.username} (ID: #{sa.id})")
                info("       Project role:    #{project_role_for(sa)}")
              else
                info("       Service account: ⚠ NOT CONFIGURED")
              end
            end
          end
        end

        def check_duo_code_review
          section("8. Duo Code Review for Project: #{project.full_path}")

          check_duo_code_review_enabled
          check_duo_code_review_availability
          check_duo_code_review_automatic_review
        end

        def check_duo_code_review_enabled
          code_review_flow = ::Ai::Catalog::FoundationalFlow.code_review_v1
          if code_review_flow&.catalog_item
            cr_item_id = code_review_flow.catalog_item.id
            if enabled_catalog_items.key?(cr_item_id)
              ok("code_review/v1 flow is enabled (catalog item ID: #{cr_item_id})")
            else
              warn("code_review/v1 flow is NOT enabled — required for DAP-mode Duo Code Review")
              info("Catalog item ID for code_review/v1: #{cr_item_id}")
            end
          else
            warn("code_review/v1 foundational flow catalog item not found")
          end
        end

        def check_duo_code_review_availability
          settings_available = ::Gitlab::Duo::CodeReview.automatic_review_available?(project)
          dap_available = project.duo_code_review_dap_available?
          has_enterprise_addon = project.namespace.has_active_add_on_purchase?([:duo_enterprise])
          consent_given = root_ancestor.consented_to?(:code_review_flow_dap_routing)

          info("automatic_review_available?:                      #{settings_available ? '✔ yes' : '✗ no'}")
          info("duo_code_review_dap_available?:                   #{dap_available ? '✔ yes (DAP mode)' : '✗ no'}")
          info("Duo Enterprise add-on purchase:                   #{has_enterprise_addon ? '✔ yes' : '✗ no'}")
          info("Code Review Flow consent given:                   #{consent_given ? '✔ yes' : '✗ no'}")

          output

          return print_duo_code_review_unavailable unless settings_available

          ok("Duo Code Review can be configured for this project")
          print_duo_code_review_mode(dap_available, has_enterprise_addon, consent_given)
          print_duo_code_review_routing_caveat
        end

        def print_duo_code_review_unavailable
          error("Duo Code Review is NOT available for this project")
          info("Requirements not met (see checks above):")
          info("  - Duo features must be enabled (instance + namespace + project)")
          info("  - EITHER: foundational flows enabled + code_review/v1 flow active + :duo_workflow stage ok")
          info("  - OR: active Duo Enterprise add-on purchase on the namespace")
        end

        def print_duo_code_review_mode(dap_available, has_enterprise_addon, consent_given)
          unless dap_available
            info("Mode: Classic - non-agentic Duo Enterprise code review") if has_enterprise_addon
            return
          end

          unless has_enterprise_addon
            info("Mode: DAP (Duo Agent Platform) - extended agentic code review")
            return
          end

          print_duo_enterprise_routing(consent_given)
        end

        def print_duo_enterprise_routing(consent_given)
          if consent_given
            info("Mode: DAP - Duo Enterprise seat holders are routed through Code Review Flow (consent given)")
          else
            info("Mode: Classic for Duo Enterprise seat holders - Duo Enterprise seat assignment still takes " \
              "priority")
            info("  Reason: consent has not been given for this namespace yet")
            info("  To activate DAP routing: a group Owner must confirm Code Review Flow in the group's " \
              "GitLab Duo settings")
          end

          info("Note: users without a Duo Enterprise seat (e.g. Duo Pro/Core) are unaffected by the above " \
            "and are always routed to Code Review Flow when available.")
        end

        def print_duo_code_review_routing_caveat
          info("Note: this reflects the namespace's Duo Enterprise add-on, not any specific reviewing user's " \
            "seat assignment - actual routing is evaluated per user, and an internal-testing override " \
            "(duo_code_review_dap_internal_users) can also force DAP for a given user regardless of the above.")
        end

        def check_duo_code_review_automatic_review
          auto_review_enabled = project.auto_duo_code_review_enabled

          output
          output("  #{THIN_SEPARATOR}")
          output("  Auto Duo Code Review setting (triggers review on every new MR)")
          output("  #{THIN_SEPARATOR}")

          if auto_review_enabled
            ok("auto_duo_code_review_enabled = true — Duo will review new merge requests automatically")
          else
            warn("auto_duo_code_review_enabled = false — automatic MR review is OFF for this project")
            info("Enable it in: Settings > Merge requests > Duo Code Review")
          end
        end

        def project_role_for(user)
          access_level = project.team.max_member_access_for_user(user)

          if access_level == ::ProjectMember::NO_ACCESS
            "⚠ No access (not a member of this project)"
          else
            ::Gitlab::Access.human_access(access_level)
          end
        end

        def output(string = nil)
          puts string.to_s.first(MAX_COLS)
        end
      end
    end
  end
end
