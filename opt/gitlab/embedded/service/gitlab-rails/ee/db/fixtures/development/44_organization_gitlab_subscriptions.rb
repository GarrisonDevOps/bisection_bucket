# frozen_string_literal: true

# Nothing writes to this table until the nomination flows land (see
# https://gitlab.com/groups/gitlab-org/-/work_items/23707). This fixture exists so
# db:migrate:multi-version-upgrade has a row to exercise.
Gitlab::Seeder.quiet do
  user = Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
  next warn "\nSkipping organization_gitlab_subscriptions seeds: no admin user available" unless user

  organization = Organizations::Organization.find_by(path: 'billed-organization')

  if organization.nil?
    candidate = Organizations::Organization.new(path: 'billed-organization', name: 'Billed Organization')

    if candidate.save
      organization = candidate
    else
      # A self-managed instance outside dev and test keeps only the default organization, and that
      # is the one refusal worth falling back from. Any other is a fault and stops the seed.
      single_organization_only = candidate.errors.added?(
        :base, s_('Organization|Only one organization is allowed on this instance.'))
      raise ActiveRecord::RecordInvalid, candidate unless single_organization_only

      warn "\nBilled organization not created: #{candidate.errors.full_messages.to_sentence}"
    end
  end

  # Outside dev and test a self-managed instance accepts only the default organization, and the
  # subscription link below rejects that one, so there the subscription is seeded without a link.
  organization ||= Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin_organization
  next warn "\nSkipping organization_gitlab_subscriptions seeds: no organization available" unless organization

  organization.add_owner(user) unless organization.owner?(user)

  group = Group.find_by_full_path('billed-organization-group') ||
    Groups::CreateService.new(
      user, name: 'Billed Organization Group', path: 'billed-organization-group', organization_id: organization.id
    ).execute.payload[:group]

  unless group.persisted?
    next warn "\nSkipping organization_gitlab_subscriptions seeds: #{group.errors.full_messages.to_sentence}"
  end

  plan = Plan.find_or_create_by!(name: Plan::ULTIMATE) { |p| p.title = p.name.titleize }
  subscription = GitlabSubscription.find_or_create_by!(namespace: group) do |s|
    s.hosted_plan = plan
    s.seats = 10
    s.start_date = Date.current
  end

  unless organization.default?
    Organizations::OrganizationGitlabSubscription.find_or_create_by!(
      organization: organization, gitlab_subscription: subscription
    )
  end

  print '.'
end
