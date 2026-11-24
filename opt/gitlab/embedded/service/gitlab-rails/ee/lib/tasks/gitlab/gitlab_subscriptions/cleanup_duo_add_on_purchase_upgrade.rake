# frozen_string_literal: true

# Helps to cleanup during Duo upgrade wrongly provisioned Duo add-on purchases
# See also https://gitlab.com/gitlab-org/gitlab/-/issues/499698
#
# This rake task is only suitable for a wrongly provisioned Duo Enterprise add-on purchase,
# where the Duo Pro add-on purchase should have been upgraded to Duo Enterprise.
# This task does not account for a wrongly provisioned Duo Pro add-on purchase.
# We need the cleanup to keep the previously created user add-on seat assignments.
#
# 1. Fetch Duo Enterprise add-on purchase
# 2. Fetch Duo Pro add-on purchase
# 4. Delete Duo Enterprise add-on purchase
# 5. Upgrade Duo Pro add-on purchase to Duo Enterprise
#
# @param namespace_id - ID of namespace which needs a cleanup
#
# @example
#   bundle exec rake "gitlab:cleanup:duo_add_on_purchase_upgrade[1234]"

namespace :gitlab do
  namespace :cleanup do
    desc 'Cleanup Duo add-on purchases upgrade'
    task :duo_add_on_purchase_upgrade, [:namespace_id] => :gitlab_environment do |_t, args|
      namespace_id = args.namespace_id.presence
      raise(ArgumentError, 'Namespace ID is required') unless namespace_id

      namespace = Namespace.find_by(id: namespace_id)
      raise(ArgumentError, 'Namespace does not exist') unless namespace

      duo_pro = GitlabSubscriptions::AddOnPurchase
        .by_namespace(namespace)
        .for_gitlab_duo_pro.first

      duo_enterprise = GitlabSubscriptions::AddOnPurchase
        .by_namespace(namespace)
        .for_duo_enterprise.first

      unless duo_pro && duo_enterprise
        raise(
          ArgumentError,
          "Expected both Duo add-ons. Duo Pro ID: #{duo_pro&.id}, Duo Enterprise ID: #{duo_enterprise&.id}"
        )
      end

      puts "Successfully destroyed the Duo Enterprise add-on purchase" if duo_enterprise.destroy

      if duo_pro.update(add_on: GitlabSubscriptions::SystemDefined::AddOn.find_by(name: "duo_enterprise"))
        puts "Successfully upgraded Duo Pro to Duo Enterprise"
      end

      puts "Cleanup finished 🎉"
    end
  end
end
