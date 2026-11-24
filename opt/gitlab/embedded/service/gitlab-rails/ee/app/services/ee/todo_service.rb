# frozen_string_literal: true

module EE
  module TodoService
    extend ::Gitlab::Utils::Override

    def duo_core_access_granted(users)
      user_access_granted(users, ::Todo::DUO_CORE_ACCESS_GRANTED, &:duo_code_review_bot)
    end

    def orbit_access_granted(users)
      user_access_granted(users, ::Todo::ORBIT_ACCESS_GRANTED, &:orbit_bot)
    end

    def duo_pro_access_granted(user)
      attributes = {
        target_id: user.id,
        target_type: ::User,
        action: ::Todo::DUO_PRO_ACCESS_GRANTED,
        author_id: ::Users::Internal.in_organization(user.organization_id).duo_code_review_bot.id,
        organization_id: user.organization_id
      }
      create_todos(user, attributes, nil, nil)
    end

    def duo_enterprise_access_granted(user)
      attributes = {
        target_id: user.id,
        target_type: ::User,
        action: ::Todo::DUO_ENTERPRISE_ACCESS_GRANTED,
        author_id: ::Users::Internal.in_organization(user.organization_id).duo_code_review_bot.id,
        organization_id: user.organization_id
      }
      create_todos(user, attributes, nil, nil)
    end

    def update_epic(epic, current_user, skip_users = [])
      update_issuable(epic, current_user, skip_users)
    end

    # When a merge train is aborted for some reason, we should:
    #
    #  * create a todo for each merge request participant
    #
    def merge_train_removed(merge_request)
      merge_request.merge_participants.each do |user|
        create_merge_train_removed_todo(merge_request, user)
      end
    end

    # When a merge request gets merged, we should:
    #
    #  * mark all its "Removed from Merge Train" todos as done
    #
    override :merge_merge_request
    def merge_merge_request(merge_request, current_user)
      resolve_merge_train_removed_todos(merge_request)
      super
    end

    def request_okr_checkin(work_item, assignee)
      project = work_item.project

      attributes = attributes_for_todo(project, work_item, work_item.author, ::Todo::OKR_CHECKIN_REQUESTED)

      create_todos(assignee, attributes, project.namespace, project)
    end

    def added_approver(users, merge_request)
      project = merge_request.project
      attributes = attributes_for_todo(project, merge_request, merge_request.author, ::Todo::ADDED_APPROVER)

      create_todos(users, attributes, project.namespace, project)
    end

    def duo_workflow_input_required(workflow)
      user = workflow.user
      project = workflow.project
      return unless project

      attributes = attributes_for_todo(project, workflow, user, ::Todo::DUO_WORKFLOW_INPUT_REQUIRED)
      create_todos(user, attributes, project.namespace, project)
    end

    def resolve_duo_workflow_input_required_todo(workflow)
      resolve_todos_with_attributes_for_target(
        workflow,
        { action: ::Todo::DUO_WORKFLOW_INPUT_REQUIRED, users: [workflow.user] }
      )
    end

    private

    def user_access_granted(users, action)
      attributes = {
        target_type: ::User.name,
        action: action
      }

      eligible_users = users_who_have_not_received_notification(attributes, users)
      eligible_users_per_org = eligible_users.group_by(&:organization_id)

      eligible_users_per_org.each do |org_id, eligible_users_in_org|
        author = yield ::Users::Internal.in_organization(org_id)

        bulk_insert_todos_for_user_target_type(
          eligible_users_in_org,
          attributes.merge(author_id: author.id)
        )
      end

      ::Users::UpdateTodoCountCacheService.new(eligible_users.map(&:id)).execute
      enqueue_badge_sync(eligible_users.map(&:id))
    end

    def users_who_have_not_received_notification(attributes, users)
      finder_attributes = attributes.except(:author_id).transform_keys do |key|
        case key
        when :action then :action_id
        when :target_type then :type
        end
      end

      filtered_users = ::TodosFinder.new(users: users, **finder_attributes.merge(state: :all)).execute.distinct_user_ids

      users.reject { |user| filtered_users.include?(user.id) }
    end

    override :attributes_for_target
    def attributes_for_target(target)
      attributes = super

      if target.is_a?(Epic)
        attributes[:group_id] = target.group_id
      elsif target.is_a?(WikiPage::Meta)
        attributes[:group_id] = target.namespace_id
      end

      attributes
    end

    def create_merge_train_removed_todo(merge_request, user)
      project = merge_request.project
      attributes = attributes_for_todo(project, merge_request, user, ::Todo::MERGE_TRAIN_REMOVED)
      create_todos(user, attributes, project.namespace, project)
    end

    def bulk_insert_todos_for_user_target_type(users, attributes)
      bulk_insert_todos(users, attributes) do |user, attrs|
        attrs.merge(user_id: user.id, target_id: user.id, organization_id: user.organization_id)
      end
    end
  end
end
