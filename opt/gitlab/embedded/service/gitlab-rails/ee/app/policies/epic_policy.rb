# frozen_string_literal: true

class EpicPolicy < BasePolicy
  delegate { @subject.group }

  condition(:is_group_member) { @subject.group.member?(@user) }

  condition(:service_desk_enabled) do
    @subject.group.has_project_with_service_desk_enabled?
  end

  desc 'Epic is confidential'
  condition(:confidential, scope: :subject) do
    @subject.confidential?
  end

  condition(:related_epics_available, scope: :subject) do
    @subject.group.licensed_feature_available?(:related_epics)
  end

  condition(:subepics_available, scope: :subject) do
    @subject.group.licensed_feature_available?(:subepics)
  end

  condition(:summarize_notes_allowed) do
    next false unless @user

    ::Gitlab::Llm::FeatureAuthorizer.new(
      container: subject.group,
      feature_name: :summarize_comments,
      user: @user
    ).allowed?
  end

  condition(:locked, scope: :subject, score: 0) { @subject.work_item.discussion_locked? }

  rule { can?(:read_epic) }.policy do
    enable :read_epic_iid
    enable :read_note
    enable :read_issuable_participables
    enable :read_issuable
  end

  rule { can?(:read_epic) & ~anonymous }.policy do
    enable :create_note
  end

  rule { can?(:create_note) }.enable :award_emoji

  rule { ~can?(:read_epic) }.policy do
    prevent :award_emoji
    prevent :read_note
  end

  desc 'User cannot read confidential epics'
  rule { confidential & ~can?(:read_confidential_epic) }.policy do
    prevent :create_epic
    prevent :update_epic
    prevent :admin_epic
    prevent :destroy_epic
    prevent :create_note
    prevent :award_emoji
    prevent :read_note
  end

  rule { ~can?(:read_epic) }.policy do
    prevent :admin_epic_relation
    prevent :read_epic_relation
    prevent :read_epic_link_relation
  end

  # Used to check permissions of subepics (child-parent relation)
  rule { can?(:admin_epic_relation) & subepics_available }.policy do
    enable :admin_epic_tree_relation
    enable :create_epic_tree_relation
  end

  # Used to check permissions of related epic links (related/blocked/blocking relation)
  rule { can?(:admin_epic_relation) & related_epics_available }.policy do
    enable :admin_epic_link_relation
  end

  # Special case to not prevent support bot
  # assigning issues to confidential epics using quick actions
  # when group has projects with service desk enabled.
  rule do
    confidential &
      ~can?(:read_confidential_epic) &
      ~(support_bot & service_desk_enabled)
  end.policy do # rubocop:disable Style/MultilineBlockChain -- Refactor in progress
    prevent :read_epic
    prevent :read_epic_iid
  end

  rule { ~anonymous & can?(:read_epic) }.policy do
    enable :create_todo
  end

  rule { can?(:update_epic) }.policy do
    enable :set_epic_metadata
    enable :set_confidentiality
  end

  rule { summarize_notes_allowed & can?(:read_epic) }.policy do
    enable :summarize_comments
  end

  rule { locked & ~is_group_member }.policy do
    prevent :create_note
    prevent :admin_note
    prevent :update_note
    prevent :delete_note
    prevent :award_emoji
  end
end
