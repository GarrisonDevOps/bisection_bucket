# frozen_string_literal: true

direct :subscription_portal_legacy_sign_in do
  Addressable::URI.join(subscription_portal_url, '/customers/sign_in?legacy=true').to_s
end

direct :subscription_portal_manage do
  Addressable::URI.join(subscription_portal_url, '/subscriptions').to_s
end

direct :subscription_portal_graphql do
  Addressable::URI.join(subscription_portal_url, '/graphql').to_s
end

direct :subscription_portal_more_minutes do
  Addressable::URI.join(subscription_portal_url, '/buy_pipeline_minutes').to_s
end

direct :subscription_portal_more_storage do
  Addressable::URI.join(subscription_portal_url, '/buy_storage').to_s
end

direct :subscription_portal_gitlab_plans do
  Addressable::URI.join(subscription_portal_url, '/gitlab_plans').to_s
end

direct :subscription_portal_edit_account do
  Addressable::URI.join(subscription_portal_url, '/customers/edit').to_s
end

direct :subscription_portal_billing_accounts do
  Addressable::URI.join(subscription_portal_url, '/billing_accounts').to_s
end

direct :subscription_portal_add_extra_seats do |group_id|
  Addressable::URI.join(subscription_portal_url, "/gitlab/namespaces/#{group_id}/extra_seats").to_s
end

direct :subscription_portal_add_saas_duo_pro_seats do |group_id|
  Addressable::URI.join(subscription_portal_url, "/gitlab/namespaces/#{group_id}/duo_pro_seats").to_s
end

direct :subscription_portal_add_sm_duo_pro_seats do |subscription_name|
  Addressable::URI.join(subscription_portal_url, "/gitlab/subscriptions/#{subscription_name}/duo_pro_seats").to_s
end

direct :subscription_portal_upgrade_subscription do |group_id, plan_id|
  Addressable::URI.join(subscription_portal_url, "/gitlab/namespaces/#{group_id}/upgrade/#{plan_id}").to_s
end

direct :subscription_portal_renew_subscription do |group_id|
  Addressable::URI.join(subscription_portal_url, "/gitlab/namespaces/#{group_id}/renew").to_s
end

direct :subscription_portal_renew_subscription_by_name do |subscription_name|
  Addressable::URI.join(subscription_portal_url, "/subscriptions/#{ERB::Util.url_encode(subscription_name)}/renew").to_s
end

direct :subscription_portal_new_subscription do
  Addressable::URI.join(subscription_portal_url, "/subscriptions/new").to_s
end

# Legacy Customers Portal upgrade, keyed by subscription name: the unified purchase flow can't change a tier yet.
# The GitLab.com upgrade above (subscription_portal_upgrade_subscription) is keyed by namespace and plan instead.
direct :subscription_portal_upgrade_self_managed_subscription do |subscription_name|
  encoded_name = ERB::Util.url_encode(subscription_name)

  Addressable::URI.join(subscription_portal_url, "/subscriptions/#{encoded_name}/upgrade/new").to_s
end

direct :subscription_portal_new_purchase do
  Addressable::URI.join(subscription_portal_url, '/subscriptions/purchases/gitlab').to_s
end

direct :subscription_portal_gitlab_com_purchase_credits do |group_id|
  Addressable::URI.join(subscription_portal_url, '/subscriptions/purchases/gitlab').tap do |uri|
    uri.query_values = { deployment_type: 'gitlab_com', plan_type: 'gitlab_credits', gl_namespace_id: group_id }
  end.to_s
end

direct :subscription_portal_self_managed_purchase_credits do |options = {}|
  Addressable::URI.join(subscription_portal_url, '/subscriptions/purchases/gitlab').tap do |uri|
    uri.query_values = { deployment_type: 'self_managed', plan_type: 'gitlab_credits' }.merge(options.compact)
  end.to_s
end
