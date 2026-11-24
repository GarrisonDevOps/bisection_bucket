# frozen_string_literal: true

# Seeds the granular scope and feature flag strategy tables, which are empty in the upgrade stop
# dump, so migrations touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::TokensAndFeatureFlags # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  FLAG_NAME = 'seeded_user_list_flag'
  LIST_NAME = 'Seeded user list'

  # Each table hangs off a different parent, so each one is guarded on its own.
  def seed!
    seed_granular_scope_link
    seed_strategy_user_list
  end

  private

  # Nothing validates that the three organizations agree, so the token is taken from the scope's
  # organization rather than picked on its own, which is the only combination the app would write.
  def seed_granular_scope_link
    scope = Authz::GranularScope.order(:id).first
    return unless scope

    token = PersonalAccessToken.where(organization_id: scope.organization_id).order(:id).first
    return if token.nil? ||
      Authz::PersonalAccessTokenGranularScope.exists?(personal_access_token_id: token.id, granular_scope_id: scope.id)

    Authz::PersonalAccessTokenGranularScope.create!(
      organization_id: scope.organization_id, personal_access_token: token, granular_scope: scope)
    print '.'
  end

  # Only a `gitlabUserList` strategy may carry a user list, and the list has to sit in the feature
  # flag's own project, so the three are created together and the join row follows from that.
  def seed_strategy_user_list
    project = Project.order(:id).first
    return if project.nil? || Operations::FeatureFlags::StrategyUserList.exists?

    flag = Operations::FeatureFlag.find_by(project: project, name: FLAG_NAME) ||
      Operations::FeatureFlag.create!(project: project, name: FLAG_NAME, active: true)
    user_list = Operations::FeatureFlags::UserList.find_by(project: project, name: LIST_NAME) ||
      Operations::FeatureFlags::UserList.create!(project: project, name: LIST_NAME, user_xids: '1,2')

    Operations::FeatureFlags::Strategy.create!(
      feature_flag: flag, name: Operations::FeatureFlags::Strategy::STRATEGY_GITLABUSERLIST,
      user_list: user_list)
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating token and feature flag data"

  Gitlab::Seeder::TokensAndFeatureFlags.new.seed!
end
