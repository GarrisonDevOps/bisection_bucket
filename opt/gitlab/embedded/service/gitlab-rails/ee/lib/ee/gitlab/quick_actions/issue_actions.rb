# frozen_string_literal: true

module EE
  module Gitlab
    module QuickActions
      module IssueActions
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::Gitlab::QuickActions::Dsl

        included do
          desc { _('Remove from epic') }
          explanation { _('Removes an issue from an epic.') }
          execution_message { _('Removed an issue from an epic.') }
          types Issue
          condition do
            quick_action_target.persisted? &&
              quick_action_target.supports_epic? &&
              quick_action_target.project.group&.feature_available?(:epics) &&
              Ability.allowed?(current_user, :"admin_#{quick_action_target.to_ability_name}_relation", quick_action_target)
          end
          command :remove_epic do
            @updates[:epic] = nil
          end

          desc { _('Promote issue to an epic') }
          explanation { _('Promote issue to an epic') }
          icon 'confidential'
          types Issue
          condition do
            quick_action_target.can_be_promoted_to_epic?(current_user)
          end
          command :promote do
            @updates[:promote_to_epic] = true

            @execution_message[:promote] = success_msg[:promote]
          end

          desc { _('Set iteration') }
          explanation do |iteration, _|
            _("Sets the iteration to %{iteration_reference}.") % { iteration_reference: iteration.to_reference } if iteration
          end
          execution_message do |iteration, error_message|
            if iteration
              _("Set the iteration to %{iteration_reference}.") % { iteration_reference: iteration.to_reference }
            elsif error_message
              error_message
            end
          end
          params '*iteration:"iteration name"|<ID> or [cadence:"cadence title"|<ID>] <--current | --next>'
          types Issue
          condition do
            quick_action_target.supports_iterations? &&
              Ability.allowed?(current_user, :"admin_#{quick_action_target.to_ability_name}", project) &&
              quick_action_target.project.group&.feature_available?(:iterations) &&
              has_iterations?(project)
          end
          parse_params do |params|
            iteration, error_code = if params.match? ::Iteration.reference_pattern
                                      # User specified a reference to an iteration e.g., `/iteration *iteration:foobar`
                                      find_iteration(params)
                                    elsif params.match? ::Iterations::Cadence.reference_pattern
                                      # User specified a reference to an iterations cadence e.g., `/iteration [cadence:foobar] --next`
                                      find_iteration_for_cadence(params)
                                    else
                                      # User did not specify a reference e,g., `/iteration --next`
                                      find_iteration_from_default_cadence(params)
                                    end

            [iteration, iteration_error_message(error_code)]
          end
          command :iteration do |iteration, _|
            @updates[:iteration] = iteration if iteration
          end

          desc { _('Remove iteration') }
          explanation do
            _("Removes %{iteration_reference} iteration.") % { iteration_reference: quick_action_target.iteration.to_reference(format: :name) }
          end
          execution_message do
            _("Removed %{iteration_reference} iteration.") % { iteration_reference: quick_action_target.iteration.to_reference(format: :name) }
          end
          types Issue
          condition do
            quick_action_target.supports_iterations? &&
              quick_action_target.persisted? &&
              quick_action_target.sprint_id? &&
              quick_action_target.project.group&.feature_available?(:iterations) &&
              Ability.allowed?(current_user, :"admin_#{quick_action_target.to_ability_name}", project)
          end
          command :remove_iteration do
            @updates[:iteration] = nil
          end

          desc { _('Publish to status page') }
          explanation { _('Publishes this issue to the associated status page.') }
          types Issue
          condition do
            StatusPage::MarkForPublicationService.publishable?(project, current_user, quick_action_target)
          end
          command :publish do
            if ::Gitlab::StatusPage.mark_for_publication(project, current_user, quick_action_target).success?
              ::Gitlab::StatusPage.trigger_publish(project, current_user, quick_action_target, action: :init)
              @execution_message[:publish] = _('Issue published on status page.')
            else
              @execution_message[:publish] = _('Failed to publish issue on status page.')
            end
          end

          desc { _('Set health status') }
          explanation do |health_status|
            _("Sets health status to %{health_status}.") % { health_status: health_status } if health_status
          end

          params "<#{::Issue.health_statuses.keys.join('|')}>"
          types Issue
          condition do
            quick_action_target.supports_health_status? &&
              Ability.allowed?(current_user, :"admin_#{quick_action_target.to_ability_name}", quick_action_target)
          end
          parse_params do |health_status|
            find_health_status(health_status)
          end
          command :health_status do |health_status|
            if health_status
              @updates[:health_status] = health_status
              @execution_message[:health_status] = _("Set health status to %{health_status}.") % { health_status: health_status }
            end
          end

          desc { _('Clear health status') }
          explanation { _('Clears health status.') }
          execution_message { _('Cleared health status.') }
          types Issue
          condition do
            quick_action_target.persisted? &&
              quick_action_target.supports_health_status? &&
              quick_action_target.health_status &&
              Ability.allowed?(current_user, :"admin_#{quick_action_target.to_ability_name}", quick_action_target)
          end
          command :clear_health_status do
            @updates[:health_status] = nil
          end

          desc { _('Escalate this incident') }
          explanation { _('Starts escalations for this incident') }
          params '<policy name>'
          types Issue
          condition do
            Ability.allowed?(current_user, :update_escalation_status, quick_action_target) &&
              quick_action_target.escalation_policies_available?
          end
          command :page do |escalation_policy_name|
            policy = ::IncidentManagement::EscalationPoliciesFinder.new(current_user, quick_action_target.project, name: escalation_policy_name).execute.first

            if policy.nil?
              @execution_message[:page] = _("Policy '%{escalation_policy_name}' does not exist.") % { escalation_policy_name: escalation_policy_name }
            elsif policy.id == quick_action_target.escalation_status&.policy_id
              @execution_message[:page] = _("This incident is already escalated with '%{escalation_policy_name}'.") % { escalation_policy_name: escalation_policy_name }
            else
              @updates[:escalation_status] = { policy: policy }
              @execution_message[:page] = _('Started escalation for this incident.')
            end
          end

          desc { _('Adds a resource link') }
          explanation { _('Adds a resource link for this incident.') }
          params do
            '<url> <link description (optional)>'
          end
          types Issue
          condition do
            quick_action_target.issuable_resource_links_available? &&
              Ability.allowed?(current_user, :admin_issuable_resource_link, quick_action_target)
          end
          parse_params do |resource_link_params|
            parse_resource_link_params(resource_link_params)
          end
          command :link do |link, link_text = nil|
            result = add_resource_link(link, link_text)
            @execution_message[:link] = result.message
          end
        end

        private

        override :zoom_link_service
        def zoom_link_service
          if quick_action_target.issuable_resource_links_available?
            ::IncidentManagement::IssuableResourceLinks::ZoomLinkService.new(project: quick_action_target.project, current_user: current_user, incident: quick_action_target)
          else
            super
          end
        end

        override :zoom_link_params
        def zoom_link_params
          if quick_action_target.issuable_resource_links_available?
            '<Zoom meeting URL> <link description (optional)>'
          else
            super
          end
        end

        override :add_zoom_link
        def add_zoom_link(link, link_text)
          if quick_action_target.issuable_resource_links_available?
            zoom_link_service.add_link(link, link_text)
          else
            super
          end
        end

        override :merge_updates
        def merge_updates(result, update_hash)
          super unless quick_action_target.issuable_resource_links_available?
        end

        def find_health_status(health_status_param)
          return unless health_status_param

          health_status_param = health_status_param.downcase
          health_statuses = ::Issue.health_statuses.keys.map(&:downcase)

          health_statuses.include?(health_status_param) && health_status_param
        end

        def has_iterations?(project)
          find_iterations(project, state: 'opened').any? || find_iterations(project, state: 'upcoming').any?
        end

        def find_iterations(project, params = {})
          parent_params = { parent: project.group, include_ancestors: true }

          ::IterationsFinder.new(current_user, params.merge(parent_params)).execute
        end

        def find_iteration_for_cadence(params)
          cadence = extract_references(params, :iterations_cadence).first

          return [nil, :cadence_not_found] unless cadence
          return [nil, :missing_option] unless params.end_with?('--next', '--current')

          if params.end_with?('--next')
            iteration = cadence.upcoming_iterations.first
            return [nil, :no_upcoming_iteration_found] unless iteration
          elsif params.end_with?('--current')
            iteration = cadence.current_iteration
            return [nil, :no_current_iteration_found] unless iteration
          end

          [iteration, nil]
        end

        def find_iteration_from_default_cadence(params)
          return [nil, :missing_option] unless params.end_with?('--next', '--current')

          cadences = ::Iterations::CadencesFinder
                        .new(current_user, project.group, include_ancestor_groups: true)
                        .execute

          return [nil, :multiple_cadences] unless cadences.one?

          cadence = cadences.first

          if params.end_with?('--next')
            cadence.upcoming_iterations.first
          elsif params.end_with?('--current')
            cadence.current_iteration
          end
        end

        def find_iteration(params)
          iteration = extract_references(params, :iteration).first
          return [iteration, nil] if iteration

          [nil, :iteration_not_found]
        end

        def iteration_error_message(code)
          case code
          when :no_upcoming_iteration_found
            _('Could not apply iteration command. No upcoming iteration found for the cadence.')
          when :no_current_iteration_found
            _('Could not apply iteration command. No current iteration found for the cadence.')
          when :missing_option
            _('Could not apply iteration command. Missing option --current or --next.')
          when :iteration_not_found
            _('Could not apply iteration command. Failed to find the referenced iteration.')
          when :cadence_not_found
            _('Could not apply iteration command. Failed to find the referenced iteration cadence.')
          when :multiple_cadences
            _('Could not apply iteration command. There are multiple cadences but no cadence is specified.')
          end
        end

        def parse_resource_link_params(params)
          return unless params

          link_params = params.split(' ', 2)
          link = link_params[0]

          return unless link

          link_text = link_params[1]&.strip
          [link, link_text.presence]
        end

        def add_resource_link(link, link_text)
          resource_link = ::IncidentManagement::IssuableResourceLinks::CreateService.new(quick_action_target,
            current_user, { link: link, link_text: link_text }).execute

          if resource_link.success?
            ServiceResponse.success(message: _('Resource link added'))
          else
            ServiceResponse.error(message: _('Failed to add a resource link'))
          end
        end
      end
    end
  end
end
