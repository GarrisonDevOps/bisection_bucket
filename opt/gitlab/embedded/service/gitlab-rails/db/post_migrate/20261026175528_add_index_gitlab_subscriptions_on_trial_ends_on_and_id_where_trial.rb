# frozen_string_literal: true

class AddIndexGitlabSubscriptionsOnTrialEndsOnAndIdWhereTrial < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  disable_ddl_transaction!

  TABLE_NAME = :gitlab_subscriptions
  INDEX_NAME = :index_gitlab_subscriptions_on_trial_ends_on_and_id_where_trial

  def up
    add_concurrent_index TABLE_NAME, [:trial_ends_on, :id], where: 'trial = true', name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end
end
